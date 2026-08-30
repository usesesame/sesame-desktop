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
    browser_pipe::PipePeer,
    browser_protocol::{
        parse_card_fields, parse_identity_fields, BrowserRequest, BrowserResponse, CardFillFields,
        IdentityFillFields, MAX_CREDENTIAL_FIELD_BYTES, MAX_NATIVE_MESSAGE_BYTES,
    },
    diagnostics,
    vault::{random_id, Card, Identity, TaggedItem, VaultEntry, VaultState},
};

use crate::browser_host::HOST_FILE_NAME;

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(30);
const APPROVAL_POLL: Duration = Duration::from_millis(200);
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
struct BrowserFillCancelledEvent {
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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserSaveCancelledEvent {
    approval_id: String,
    reason: &'static str,
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
struct BrowserIdentityCancelledEvent {
    approval_id: String,
    reason: &'static str,
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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserCardCancelledEvent {
    approval_id: String,
    reason: &'static str,
}

enum ApprovalDecision {
    Denied,
    InvalidSelection,
    Login(String),
}

enum SaveDecision {
    Approved,
    Declined,
}

enum IdentityDecision {
    Denied,
    InvalidSelection,
    Identity(String),
}

enum CardDecision {
    Denied,
    InvalidSelection,
    Card(String),
}

struct PendingApproval {
    approval_id: String,
    request_id: String,
    origin: NormalizedOrigin,
    session_epoch: u64,
    candidate_ids: HashSet<String>,
    request_event: Option<BrowserFillRequestEvent>,
    deadline: Instant,
    sender: SyncSender<ApprovalDecision>,
}

struct PendingSave {
    approval_id: String,
    request_id: String,
    origin: NormalizedOrigin,
    session_epoch: u64,
    kind: SaveKind,
    title: String,
    username: String,
    password: zeroize::Zeroizing<String>,
    /// Exact-origin targets for `update`; the resolve command must name which one.
    candidates: Vec<BrowserFillCandidate>,
    request_event: Option<BrowserSaveRequestEvent>,
    deadline: Instant,
    sender: SyncSender<SaveDecision>,
}

impl Drop for PendingSave {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
    }
}

/// Held credential, returned to the command layer only while the approval is still bound.
pub struct SavePayload {
    pub kind: SaveKind,
    pub title: String,
    pub username: String,
    pub password: String,
    pub origin: String,
    pub epoch: u64,
    pub candidates: Vec<BrowserFillCandidate>,
}

struct PendingIdentityApproval {
    approval_id: String,
    request_id: String,
    origin: NormalizedOrigin,
    session_epoch: u64,
    candidate_ids: HashSet<String>,
    request_event: Option<BrowserIdentityRequestEvent>,
    deadline: Instant,
    sender: SyncSender<IdentityDecision>,
}

struct PendingCardApproval {
    approval_id: String,
    request_id: String,
    origin: NormalizedOrigin,
    session_epoch: u64,
    candidate_ids: HashSet<String>,
    request_event: Option<BrowserCardRequestEvent>,
    deadline: Instant,
    sender: SyncSender<CardDecision>,
}

#[derive(Default)]
struct FillInner {
    pending: Option<PendingApproval>,
    pending_save: Option<PendingSave>,
    pending_identity: Option<PendingIdentityApproval>,
    pending_card: Option<PendingCardApproval>,
    recent_request_ids: VecDeque<String>,
    grants: Vec<FillGrant>,
}

/// One approval the user chose to extend to a single origin and login for a short window.
/// Bound to the session epoch, so locking or changing the vault discards it.
struct FillGrant {
    origin: String,
    login_id: String,
    session_epoch: u64,
    expires: Instant,
}

#[derive(Default)]
pub struct BrowserFillState {
    inner: Mutex<FillInner>,
}

impl BrowserFillState {
    fn cancel_pending(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(pending) = inner.pending.take() {
                let _ = pending.sender.send(ApprovalDecision::Denied);
            }
            if let Some(pending) = inner.pending_save.take() {
                let _ = pending.sender.send(SaveDecision::Declined);
            }
            if let Some(pending) = inner.pending_identity.take() {
                let _ = pending.sender.send(IdentityDecision::Denied);
            }
            if let Some(pending) = inner.pending_card.take() {
                let _ = pending.sender.send(CardDecision::Denied);
            }
            inner.grants.clear();
        }
    }

    /// An unexpired grant for this exact origin and epoch whose login is still offered.
    fn granted_login(
        &self,
        origin: &NormalizedOrigin,
        session_epoch: u64,
        candidate_ids: &HashSet<String>,
    ) -> Option<String> {
        let mut inner = self.inner.lock().ok()?;
        let now = Instant::now();
        inner
            .grants
            .retain(|grant| grant.expires > now && grant.session_epoch == session_epoch);
        let canonical = origin.canonical();
        inner
            .grants
            .iter()
            .find(|grant| grant.origin == canonical && candidate_ids.contains(&grant.login_id))
            .map(|grant| grant.login_id.clone())
    }

    fn note_request_id(inner: &mut FillInner, request_id: &str) -> Result<(), &'static str> {
        if inner
            .recent_request_ids
            .iter()
            .any(|recent| recent == request_id)
        {
            return Err("staleRequest");
        }
        inner.recent_request_ids.push_back(request_id.to_string());
        while inner.recent_request_ids.len() > REPLAY_CACHE_SIZE {
            inner.recent_request_ids.pop_front();
        }
        Ok(())
    }

    fn begin(
        &self,
        request_id: &str,
        origin: NormalizedOrigin,
        session_epoch: u64,
        candidate_ids: HashSet<String>,
    ) -> Result<(String, Instant, Receiver<ApprovalDecision>), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        Self::note_request_id(&mut inner, request_id)?;
        if inner.pending.is_some()
            || inner.pending_save.is_some()
            || inner.pending_identity.is_some()
            || inner.pending_card.is_some()
        {
            return Err("approvalUnavailable");
        }

        let approval_id = random_id();
        let (sender, receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + APPROVAL_TIMEOUT;
        inner.pending = Some(PendingApproval {
            approval_id: approval_id.clone(),
            request_id: request_id.to_string(),
            origin,
            session_epoch,
            candidate_ids,
            request_event: None,
            deadline,
            sender,
        });
        Ok((approval_id, deadline, receiver))
    }

    fn begin_save(
        &self,
        request_id: &str,
        origin: NormalizedOrigin,
        session_epoch: u64,
        kind: SaveKind,
        title: String,
        username: String,
        password: zeroize::Zeroizing<String>,
        candidates: Vec<BrowserFillCandidate>,
    ) -> Result<(String, Instant, Receiver<SaveDecision>), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        Self::note_request_id(&mut inner, request_id)?;
        if inner.pending.is_some()
            || inner.pending_save.is_some()
            || inner.pending_identity.is_some()
            || inner.pending_card.is_some()
        {
            return Err("approvalUnavailable");
        }

        let approval_id = random_id();
        let (sender, receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + APPROVAL_TIMEOUT;
        inner.pending_save = Some(PendingSave {
            approval_id: approval_id.clone(),
            request_id: request_id.to_string(),
            origin,
            session_epoch,
            kind,
            title,
            username,
            password,
            candidates,
            request_event: None,
            deadline,
            sender,
        });
        Ok((approval_id, deadline, receiver))
    }

    fn begin_identity(
        &self,
        request_id: &str,
        origin: NormalizedOrigin,
        session_epoch: u64,
        candidate_ids: HashSet<String>,
    ) -> Result<(String, Instant, Receiver<IdentityDecision>), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        Self::note_request_id(&mut inner, request_id)?;
        if inner.pending.is_some()
            || inner.pending_save.is_some()
            || inner.pending_identity.is_some()
            || inner.pending_card.is_some()
        {
            return Err("approvalUnavailable");
        }

        let approval_id = random_id();
        let (sender, receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + APPROVAL_TIMEOUT;
        inner.pending_identity = Some(PendingIdentityApproval {
            approval_id: approval_id.clone(),
            request_id: request_id.to_string(),
            origin,
            session_epoch,
            candidate_ids,
            request_event: None,
            deadline,
            sender,
        });
        Ok((approval_id, deadline, receiver))
    }

    fn publish_identity(
        &self,
        approval_id: &str,
        request_event: BrowserIdentityRequestEvent,
    ) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending_identity.as_mut().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        pending.request_event = Some(request_event);
        Ok(())
    }

    fn pending_identity_request(&self) -> Option<BrowserIdentityRequestEvent> {
        self.inner.lock().ok().and_then(|inner| {
            let pending = inner.pending_identity.as_ref()?;
            (pending.deadline > Instant::now())
                .then(|| pending.request_event.clone())
                .flatten()
        })
    }

    fn decide_identity(
        &self,
        approval_id: &str,
        identity_id: Option<String>,
    ) -> Result<bool, &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending_identity.as_ref().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        let invalid_selection = identity_id
            .as_deref()
            .is_some_and(|identity_id| !pending.candidate_ids.contains(identity_id));
        if invalid_selection {
            pending
                .sender
                .send(IdentityDecision::InvalidSelection)
                .map_err(|_| "approvalExpired")?;
            inner.pending_identity = None;
            return Err("identityNotOffered");
        }
        let denied = identity_id.is_none();
        let decision = identity_id
            .map(IdentityDecision::Identity)
            .unwrap_or(IdentityDecision::Denied);
        pending
            .sender
            .send(decision)
            .map_err(|_| "approvalExpired")?;
        inner.pending_identity = None;
        Ok(denied)
    }

    fn revoke_identity(&self, approval_id: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            if inner
                .pending_identity
                .as_ref()
                .is_some_and(|pending| pending.approval_id == approval_id)
            {
                inner.pending_identity = None;
            }
        }
    }

    fn is_identity_bound(
        &self,
        approval_id: &str,
        request_id: &str,
        origin: &NormalizedOrigin,
        session_epoch: u64,
    ) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| {
                inner.pending_identity.as_ref().map(|pending| {
                    pending.approval_id == approval_id
                        && pending.request_id == request_id
                        && pending.origin == *origin
                        && pending.session_epoch == session_epoch
                })
            })
            .unwrap_or(false)
    }

    fn begin_card(
        &self,
        request_id: &str,
        origin: NormalizedOrigin,
        session_epoch: u64,
        candidate_ids: HashSet<String>,
    ) -> Result<(String, Instant, Receiver<CardDecision>), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        Self::note_request_id(&mut inner, request_id)?;
        if inner.pending.is_some()
            || inner.pending_save.is_some()
            || inner.pending_identity.is_some()
            || inner.pending_card.is_some()
        {
            return Err("approvalUnavailable");
        }
        let approval_id = random_id();
        let (sender, receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + APPROVAL_TIMEOUT;
        inner.pending_card = Some(PendingCardApproval {
            approval_id: approval_id.clone(),
            request_id: request_id.to_string(),
            origin,
            session_epoch,
            candidate_ids,
            request_event: None,
            deadline,
            sender,
        });
        Ok((approval_id, deadline, receiver))
    }

    fn publish_card(
        &self,
        approval_id: &str,
        request_event: BrowserCardRequestEvent,
    ) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending_card.as_mut().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        pending.request_event = Some(request_event);
        Ok(())
    }

    fn pending_card_request(&self) -> Option<BrowserCardRequestEvent> {
        self.inner.lock().ok().and_then(|inner| {
            let pending = inner.pending_card.as_ref()?;
            (pending.deadline > Instant::now())
                .then(|| pending.request_event.clone())
                .flatten()
        })
    }

    fn decide_card(
        &self,
        approval_id: &str,
        card_id: Option<String>,
    ) -> Result<bool, &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending_card.as_ref().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        if card_id
            .as_deref()
            .is_some_and(|card_id| !pending.candidate_ids.contains(card_id))
        {
            pending
                .sender
                .send(CardDecision::InvalidSelection)
                .map_err(|_| "approvalExpired")?;
            inner.pending_card = None;
            return Err("cardNotOffered");
        }
        let denied = card_id.is_none();
        pending
            .sender
            .send(
                card_id
                    .map(CardDecision::Card)
                    .unwrap_or(CardDecision::Denied),
            )
            .map_err(|_| "approvalExpired")?;
        inner.pending_card = None;
        Ok(denied)
    }

    fn revoke_card(&self, approval_id: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            if inner
                .pending_card
                .as_ref()
                .is_some_and(|pending| pending.approval_id == approval_id)
            {
                inner.pending_card = None;
            }
        }
    }

    fn is_card_bound(
        &self,
        approval_id: &str,
        request_id: &str,
        origin: &NormalizedOrigin,
        session_epoch: u64,
    ) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| {
                inner.pending_card.as_ref().map(|pending| {
                    pending.approval_id == approval_id
                        && pending.request_id == request_id
                        && pending.origin == *origin
                        && pending.session_epoch == session_epoch
                })
            })
            .unwrap_or(false)
    }

    fn publish_save(
        &self,
        approval_id: &str,
        request_event: BrowserSaveRequestEvent,
    ) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending_save.as_mut().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        pending.request_event = Some(request_event);
        Ok(())
    }

    fn pending_save_request(&self) -> Option<BrowserSaveRequestEvent> {
        self.inner.lock().ok().and_then(|inner| {
            let pending = inner.pending_save.as_ref()?;
            (pending.deadline > Instant::now())
                .then(|| pending.request_event.clone())
                .flatten()
        })
    }

    /// Credential only while bound; `decide_save` still releases the broker.
    fn save_payload_if_bound(&self, approval_id: &str) -> Option<SavePayload> {
        self.inner.lock().ok().and_then(|inner| {
            let pending = inner.pending_save.as_ref()?;
            if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
                return None;
            }
            Some(SavePayload {
                kind: pending.kind,
                title: pending.title.clone(),
                username: pending.username.clone(),
                password: pending.password.as_str().to_string(),
                origin: pending.origin.canonical(),
                epoch: pending.session_epoch,
                candidates: pending.candidates.clone(),
            })
        })
    }

    fn decide_save(&self, approval_id: &str, approved: bool) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending_save.as_ref().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        let decision = if approved {
            SaveDecision::Approved
        } else {
            SaveDecision::Declined
        };
        pending
            .sender
            .send(decision)
            .map_err(|_| "approvalExpired")?;
        inner.pending_save = None;
        Ok(())
    }

    fn revoke_save(&self, approval_id: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            if inner
                .pending_save
                .as_ref()
                .is_some_and(|pending| pending.approval_id == approval_id)
            {
                inner.pending_save = None;
            }
        }
    }

    fn is_save_bound(
        &self,
        approval_id: &str,
        request_id: &str,
        origin: &NormalizedOrigin,
        session_epoch: u64,
    ) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| {
                inner.pending_save.as_ref().map(|pending| {
                    pending.approval_id == approval_id
                        && pending.request_id == request_id
                        && pending.origin == *origin
                        && pending.session_epoch == session_epoch
                })
            })
            .unwrap_or(false)
    }

    fn publish_request(
        &self,
        approval_id: &str,
        request_event: BrowserFillRequestEvent,
    ) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending.as_mut().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        pending.request_event = Some(request_event);
        Ok(())
    }

    fn pending_request(&self) -> Option<BrowserFillRequestEvent> {
        self.inner.lock().ok().and_then(|inner| {
            let pending = inner.pending.as_ref()?;
            (pending.deadline > Instant::now())
                .then(|| pending.request_event.clone())
                .flatten()
        })
    }

    fn decide(
        &self,
        approval_id: &str,
        login_id: Option<String>,
        remember: bool,
    ) -> Result<bool, &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending.as_ref().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        let invalid_selection = login_id
            .as_deref()
            .is_some_and(|login_id| !pending.candidate_ids.contains(login_id));
        if invalid_selection {
            pending
                .sender
                .send(ApprovalDecision::InvalidSelection)
                .map_err(|_| "approvalExpired")?;
            inner.pending = None;
            return Err("loginNotOffered");
        }
        let denied = login_id.is_none();
        let grant = match (&login_id, remember) {
            (Some(login_id), true) => Some(FillGrant {
                origin: pending.origin.canonical(),
                login_id: login_id.clone(),
                session_epoch: pending.session_epoch,
                expires: Instant::now() + FILL_GRANT_DURATION,
            }),
            _ => None,
        };
        let decision = login_id
            .map(ApprovalDecision::Login)
            .unwrap_or(ApprovalDecision::Denied);
        pending
            .sender
            .send(decision)
            .map_err(|_| "approvalExpired")?;
        inner.pending = None;
        if let Some(grant) = grant {
            inner
                .grants
                .retain(|held| held.origin != grant.origin || held.login_id != grant.login_id);
            inner.grants.push(grant);
        }
        Ok(denied)
    }

    fn revoke(&self, approval_id: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            if inner
                .pending
                .as_ref()
                .is_some_and(|pending| pending.approval_id == approval_id)
            {
                inner.pending = None;
            }
        }
    }

    fn is_bound(
        &self,
        approval_id: &str,
        request_id: &str,
        origin: &NormalizedOrigin,
        session_epoch: u64,
    ) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| {
                inner.pending.as_ref().map(|pending| {
                    pending.approval_id == approval_id
                        && pending.request_id == request_id
                        && pending.origin == *origin
                        && pending.session_epoch == session_epoch
                })
            })
            .unwrap_or(false)
    }
}

pub fn cancel_pending_approvals(app: &tauri::AppHandle) {
    app.state::<BrowserFillState>().cancel_pending();
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
    match state.decide_save(approval_id, approved) {
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
                emit_save_cancelled(app, approval_id, "denied");
            }
            Ok(())
        }
        Err(_) => {
            emit_save_cancelled(app, approval_id, "expired");
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
    match state.decide(&approval_id, login_id, remember) {
        Ok(denied) => {
            diagnostics::record_browser_host_registration(
                app,
                if denied {
                    "fill_denied"
                } else {
                    "fill_approved"
                },
            );
            if denied {
                emit_cancelled(app, &approval_id, "denied");
            }
            Ok(())
        }
        Err(_) => {
            emit_cancelled(app, &approval_id, "expired");
            Err("That browser approval expired or is no longer available.".into())
        }
    }
}

pub fn pending(state: State<'_, BrowserFillState>) -> Option<BrowserFillRequestEvent> {
    state.pending_request()
}

pub fn pending_identity(state: State<'_, BrowserFillState>) -> Option<BrowserIdentityRequestEvent> {
    state.pending_identity_request()
}

pub fn pending_card(state: State<'_, BrowserFillState>) -> Option<BrowserCardRequestEvent> {
    state.pending_card_request()
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
    match state.decide_identity(&approval_id, identity_id) {
        Ok(denied) => {
            diagnostics::record_browser_host_registration(
                app,
                if denied {
                    "identity_denied"
                } else {
                    "identity_approved"
                },
            );
            if denied {
                emit_identity_cancelled(app, &approval_id, "denied");
            }
            Ok(())
        }
        Err(_) => {
            emit_identity_cancelled(app, &approval_id, "expired");
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
    match state.decide_card(&approval_id, card_id) {
        Ok(denied) => {
            diagnostics::record_browser_host_registration(
                app,
                if denied {
                    "card_denied"
                } else {
                    "card_approved"
                },
            );
            if denied {
                emit_card_cancelled(app, &approval_id, "denied");
            }
            Ok(())
        }
        Err(_) => {
            emit_card_cancelled(app, &approval_id, "expired");
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
        "capabilities" => capabilities_response(app, &request),
        "activate" => activation_response(app, &request),
        "fill" => fill_response(app, &request, peer),
        "save" => save_response(app, &mut request, peer),
        "identity" => identity_response(app, &request, peer),
        "card" => card_response(app, &request, peer),
        _ => BrowserResponse::error(&request.request_id, "Unsupported browser request."),
    };
    response_bytes(response)
}

fn activation_response(app: &AppHandle, request: &BrowserRequest) -> BrowserResponse {
    crate::desktop_shell::show_main_window(app);
    BrowserResponse::activated(&request.request_id, true)
}

fn capabilities_response(app: &AppHandle, request: &BrowserRequest) -> BrowserResponse {
    let state = app.state::<VaultState>();
    let locked = state
        .session
        .lock()
        .map(|session| session.is_none())
        .unwrap_or(true);
    BrowserResponse::capabilities(&request.request_id, true, locked)
}

fn fill_response(app: &AppHandle, request: &BrowserRequest, peer: &PipePeer) -> BrowserResponse {
    diagnostics::record_browser_host_registration(app, "fill_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::unavailable(&request.request_id, "staleRequest");
    };
    let vault = app.state::<VaultState>();
    let (epoch, candidates) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => {
                return BrowserResponse::unavailable(&request.request_id, "approvalUnavailable")
            }
        };
        let Some(session) = session.as_ref() else {
            diagnostics::record_browser_host_registration(app, "fill_locked");
            return BrowserResponse::unavailable(&request.request_id, "locked");
        };
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => {
                return BrowserResponse::unavailable(&request.request_id, "approvalUnavailable")
            }
        };
        let candidates = matching_entries(&payload.entries, &origin);
        (vault.session_epoch(), candidates)
    };
    if candidates.is_empty() {
        diagnostics::record_browser_host_registration(app, "fill_no_match");
        return BrowserResponse::unavailable(&request.request_id, "noMatch");
    }
    if candidates.len() > MAX_MATCHING_CANDIDATES {
        return BrowserResponse::unavailable(&request.request_id, "multipleMatches");
    }

    let candidate_ids: HashSet<String> = candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let fill_state = app.state::<BrowserFillState>();
    let granted = fill_state.granted_login(&origin, epoch, &candidate_ids);
    let (approval_id, deadline, receiver) =
        match fill_state.begin(&request.request_id, origin.clone(), epoch, candidate_ids) {
            Ok(value) => value,
            Err(reason) => return BrowserResponse::unavailable(&request.request_id, reason),
        };

    // A live grant resolves the approval without prompting. Every check after the
    // decision still runs, so the vault, origin, and peer are revalidated as usual.
    if let Some(login_id) = granted {
        if fill_state
            .decide(&approval_id, Some(login_id), false)
            .is_err()
        {
            fill_state.revoke(&approval_id);
            return BrowserResponse::unavailable(&request.request_id, "approvalUnavailable");
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
            .publish_request(&approval_id, event.clone())
            .is_err()
        {
            fill_state.revoke(&approval_id);
            return BrowserResponse::unavailable(&request.request_id, "approvalUnavailable");
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
    ) {
        Ok(decision) => decision,
        Err(reason) => return BrowserResponse::unavailable(&request.request_id, reason),
    };
    let login_id = match decision {
        ApprovalDecision::Login(login_id) => login_id,
        ApprovalDecision::Denied => {
            return BrowserResponse::unavailable(&request.request_id, "approvalDeclined")
        }
        ApprovalDecision::InvalidSelection => {
            return BrowserResponse::unavailable(&request.request_id, "invalidSelection")
        }
    };
    if !peer.is_connected() {
        emit_cancelled(app, &approval_id, "connectionClosed");
        return BrowserResponse::unavailable(&request.request_id, "staleRequest");
    }

    // Bindings rechecked after approval under the vault lock; no credential is copied before this.
    let session = match vault.session.lock() {
        Ok(session) => session,
        Err(_) => return BrowserResponse::unavailable(&request.request_id, "approvalUnavailable"),
    };
    if vault.session_epoch() != epoch {
        emit_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(&request.request_id, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        emit_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(&request.request_id, "locked");
    };
    let Ok(item) = session.open_item(&login_id) else {
        emit_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(&request.request_id, "staleRequest");
    };
    let TaggedItem::Login(entry) = &*item else {
        emit_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(&request.request_id, "staleRequest");
    };
    if NormalizedOrigin::from_saved_url(&entry.url)
        .as_ref()
        .and_then(|saved| origin_match_kind(saved, &origin))
        .is_none()
        || !credential_fields_valid(entry)
    {
        emit_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(&request.request_id, "staleRequest");
    }
    BrowserResponse::fill_for(request, identity_value(entry), entry.password.clone())
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
            return BrowserResponse::save_unavailable(&request.request_id, "locked");
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
        return BrowserResponse::save_unavailable(&request.request_id, "multipleMatches");
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
    let (approval_id, deadline, receiver) = match fill_state.begin_save(
        &request.request_id,
        origin.clone(),
        epoch,
        kind,
        title.clone(),
        username.clone(),
        password,
        candidates.clone(),
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
        .publish_save(&approval_id, event.clone())
        .is_err()
    {
        fill_state.revoke_save(&approval_id);
        return BrowserResponse::save_unavailable(&request.request_id, "approvalUnavailable");
    }
    bring_to_foreground(app);
    let _ = app.emit("browser-save-request", event);

    match wait_for_save_decision(
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
    ) {
        Ok(SaveDecision::Approved) => BrowserResponse::saved(&request.request_id),
        Ok(SaveDecision::Declined) => {
            BrowserResponse::save_unavailable(&request.request_id, "approvalDeclined")
        }
        Err(reason) => BrowserResponse::save_unavailable(&request.request_id, reason),
    }
}

fn wait_for_save_decision(
    app: &AppHandle,
    fill_state: &BrowserFillState,
    vault: &VaultState,
    approval_id: &str,
    request_id: &str,
    origin: &NormalizedOrigin,
    epoch: u64,
    deadline: Instant,
    receiver: Receiver<SaveDecision>,
    peer: &PipePeer,
) -> Result<SaveDecision, &'static str> {
    loop {
        match receiver.try_recv() {
            Ok(decision) => return Ok(decision),
            Err(TryRecvError::Disconnected) => return Err("approvalUnavailable"),
            Err(TryRecvError::Empty) => {}
        }
        if !peer.is_connected() {
            fill_state.revoke_save(approval_id);
            emit_save_cancelled(app, approval_id, "connectionClosed");
            diagnostics::record_browser_host_registration(app, "save_connection_closed");
            return Err("staleRequest");
        }
        if Instant::now() >= deadline {
            fill_state.revoke_save(approval_id);
            emit_save_cancelled(app, approval_id, "expired");
            diagnostics::record_browser_host_registration(app, "save_timeout");
            return Err("approvalTimeout");
        }
        if !fill_state.is_save_bound(approval_id, request_id, origin, epoch) {
            if let Ok(decision) = receiver.try_recv() {
                return Ok(decision);
            }
            fill_state.revoke_save(approval_id);
            emit_save_cancelled(app, approval_id, "expired");
            return Err("approvalUnavailable");
        }
        if vault.session_epoch() != epoch {
            fill_state.revoke_save(approval_id);
            emit_save_cancelled(app, approval_id, "vaultChanged");
            diagnostics::record_browser_host_registration(app, "save_vault_changed");
            return Err("staleRequest");
        }
        thread::sleep(APPROVAL_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn emit_save_cancelled(app: &AppHandle, approval_id: &str, reason: &'static str) {
    let _ = app.emit(
        "browser-save-cancelled",
        BrowserSaveCancelledEvent {
            approval_id: approval_id.to_string(),
            reason,
        },
    );
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
            return BrowserResponse::card_unavailable(&request.request_id, "locked");
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
    let (approval_id, deadline, receiver) =
        match fill_state.begin_card(&request.request_id, origin.clone(), epoch, candidate_ids) {
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
        .publish_card(&approval_id, event.clone())
        .is_err()
    {
        fill_state.revoke_card(&approval_id);
        return BrowserResponse::card_unavailable(&request.request_id, "approvalUnavailable");
    }
    bring_to_foreground(app);
    let _ = app.emit("browser-card-request", event);
    let decision = match wait_for_card_decision(
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
    ) {
        Ok(decision) => decision,
        Err(reason) => return BrowserResponse::card_unavailable(&request.request_id, reason),
    };
    let card_id = match decision {
        CardDecision::Card(card_id) => card_id,
        CardDecision::Denied => {
            return BrowserResponse::card_unavailable(&request.request_id, "approvalDeclined")
        }
        CardDecision::InvalidSelection => {
            return BrowserResponse::card_unavailable(&request.request_id, "invalidSelection")
        }
    };
    if !peer.is_connected() {
        emit_card_cancelled(app, &approval_id, "connectionClosed");
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    }
    let session = match vault.session.lock() {
        Ok(session) => session,
        Err(_) => {
            return BrowserResponse::card_unavailable(&request.request_id, "approvalUnavailable")
        }
    };
    if vault.session_epoch() != epoch {
        emit_card_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        emit_card_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::card_unavailable(&request.request_id, "locked");
    };
    let Ok(item) = session.open_item(&card_id) else {
        emit_card_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    };
    let TaggedItem::Card(card) = &*item else {
        emit_card_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    };
    if !card_supports_fields(card, &requested_fields) {
        emit_card_cancelled(app, &approval_id, "vaultChanged");
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

#[allow(clippy::too_many_arguments)]
fn wait_for_card_decision(
    app: &AppHandle,
    fill_state: &BrowserFillState,
    vault: &VaultState,
    approval_id: &str,
    request_id: &str,
    origin: &NormalizedOrigin,
    epoch: u64,
    deadline: Instant,
    receiver: Receiver<CardDecision>,
    peer: &PipePeer,
) -> Result<CardDecision, &'static str> {
    loop {
        match receiver.try_recv() {
            Ok(decision) => return Ok(decision),
            Err(TryRecvError::Disconnected) => return Err("approvalUnavailable"),
            Err(TryRecvError::Empty) => {}
        }
        if !peer.is_connected() {
            fill_state.revoke_card(approval_id);
            emit_card_cancelled(app, approval_id, "connectionClosed");
            diagnostics::record_browser_host_registration(app, "card_connection_closed");
            return Err("staleRequest");
        }
        if Instant::now() >= deadline {
            fill_state.revoke_card(approval_id);
            emit_card_cancelled(app, approval_id, "expired");
            diagnostics::record_browser_host_registration(app, "card_timeout");
            return Err("approvalTimeout");
        }
        if !fill_state.is_card_bound(approval_id, request_id, origin, epoch) {
            if let Ok(decision) = receiver.try_recv() {
                return Ok(decision);
            }
            fill_state.revoke_card(approval_id);
            emit_card_cancelled(app, approval_id, "expired");
            return Err("approvalUnavailable");
        }
        if vault.session_epoch() != epoch {
            fill_state.revoke_card(approval_id);
            emit_card_cancelled(app, approval_id, "vaultChanged");
            diagnostics::record_browser_host_registration(app, "card_vault_changed");
            return Err("staleRequest");
        }
        thread::sleep(APPROVAL_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn emit_card_cancelled(app: &AppHandle, approval_id: &str, reason: &'static str) {
    let _ = app.emit(
        "browser-card-cancelled",
        BrowserCardCancelledEvent {
            approval_id: approval_id.to_string(),
            reason,
        },
    );
}

include!("browser_fill_identity_approval.rs");

fn approval_expires_at_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(APPROVAL_TIMEOUT)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

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
) -> Result<ApprovalDecision, &'static str> {
    loop {
        match receiver.try_recv() {
            Ok(decision) => return Ok(decision),
            Err(TryRecvError::Disconnected) => return Err("approvalUnavailable"),
            Err(TryRecvError::Empty) => {}
        }
        if !peer.is_connected() {
            fill_state.revoke(approval_id);
            emit_cancelled(app, approval_id, "connectionClosed");
            diagnostics::record_browser_host_registration(app, "fill_connection_closed");
            return Err("staleRequest");
        }
        if Instant::now() >= deadline {
            fill_state.revoke(approval_id);
            emit_cancelled(app, approval_id, "expired");
            diagnostics::record_browser_host_registration(app, "fill_timeout");
            return Err("approvalTimeout");
        }
        if !fill_state.is_bound(approval_id, request_id, origin, epoch) {
            if let Ok(decision) = receiver.try_recv() {
                return Ok(decision);
            }
            fill_state.revoke(approval_id);
            emit_cancelled(app, approval_id, "expired");
            return Err("approvalUnavailable");
        }
        if vault.session_epoch() != epoch {
            fill_state.revoke(approval_id);
            emit_cancelled(app, approval_id, "vaultChanged");
            diagnostics::record_browser_host_registration(app, "fill_vault_changed");
            return Err("staleRequest");
        }
        thread::sleep(APPROVAL_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

include!("browser_fill_matching.rs");

fn emit_cancelled(app: &AppHandle, approval_id: &str, reason: &'static str) {
    let _ = app.emit(
        "browser-fill-cancelled",
        BrowserFillCancelledEvent {
            approval_id: approval_id.to_string(),
            reason,
        },
    );
}

fn response_bytes(response: BrowserResponse) -> zeroize::Zeroizing<Vec<u8>> {
    let bytes = response
        .to_zeroizing_bytes()
        .unwrap_or_else(|_| zeroize::Zeroizing::new(Vec::new()));
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_MESSAGE_BYTES {
        zeroize::Zeroizing::new(
            serde_json::to_vec(&BrowserResponse::error(
                "invalid",
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

    /// Approve once with remember, and the next request for the same origin and login needs no prompt.
    fn approve(state: &BrowserFillState, request_id: &str, epoch: u64, remember: bool) {
        let (approval_id, _, _receiver) = state
            .begin(
                request_id,
                origin("https://example.test"),
                epoch,
                ids(&["login-a"]),
            )
            .expect("begin");
        state
            .decide(&approval_id, Some("login-a".to_string()), remember)
            .expect("decide");
    }

    #[test]
    fn a_remembered_approval_answers_the_next_request_for_the_same_login() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, true);
        assert_eq!(
            state.granted_login(&origin("https://example.test"), 7, &ids(&["login-a"])),
            Some("login-a".to_string())
        );
    }

    #[test]
    fn an_approval_without_remember_grants_nothing() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, false);
        assert_eq!(
            state.granted_login(&origin("https://example.test"), 7, &ids(&["login-a"])),
            None
        );
    }

    #[test]
    fn a_grant_does_not_cross_to_another_origin() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, true);
        assert_eq!(
            state.granted_login(&origin("https://other.test"), 7, &ids(&["login-a"])),
            None
        );
    }

    #[test]
    fn a_grant_does_not_cover_a_login_it_was_not_given_for() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, true);
        assert_eq!(
            state.granted_login(&origin("https://example.test"), 7, &ids(&["login-b"])),
            None
        );
    }

    /// Locking the vault advances the session epoch, so a grant cannot survive it.
    #[test]
    fn a_grant_dies_when_the_session_epoch_moves() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, true);
        assert_eq!(
            state.granted_login(&origin("https://example.test"), 8, &ids(&["login-a"])),
            None
        );
        // The stale grant is pruned rather than left waiting for the epoch to come back.
        assert_eq!(
            state.granted_login(&origin("https://example.test"), 7, &ids(&["login-a"])),
            None
        );
    }

    #[test]
    fn cancelling_pending_approvals_clears_every_grant() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, true);
        state.cancel_pending();
        assert_eq!(
            state.granted_login(&origin("https://example.test"), 7, &ids(&["login-a"])),
            None
        );
    }

    #[test]
    fn a_card_approval_is_consumed_and_cannot_be_replayed() {
        let state = BrowserFillState::default();
        let (approval_id, _, receiver) = state
            .begin_card(
                "card-request-1",
                origin("https://checkout.example.test"),
                7,
                ids(&["card-a"]),
            )
            .expect("begin card");

        assert!(!state
            .decide_card(&approval_id, Some("card-a".to_string()))
            .expect("approve card"));
        assert!(matches!(receiver.recv(), Ok(CardDecision::Card(card_id)) if card_id == "card-a"));
        assert!(state.pending_card_request().is_none());
        assert!(matches!(
            state.begin_card(
                "card-request-1",
                origin("https://checkout.example.test"),
                7,
                ids(&["card-a"]),
            ),
            Err("staleRequest")
        ));
    }

    #[test]
    fn a_card_not_offered_for_approval_is_never_released() {
        let state = BrowserFillState::default();
        let (approval_id, _, receiver) = state
            .begin_card(
                "card-request-2",
                origin("https://checkout.example.test"),
                7,
                ids(&["card-a"]),
            )
            .expect("begin card");

        assert_eq!(
            state.decide_card(&approval_id, Some("card-b".to_string())),
            Err("cardNotOffered")
        );
        assert!(matches!(
            receiver.recv(),
            Ok(CardDecision::InvalidSelection)
        ));
        assert!(state.pending_card_request().is_none());
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
