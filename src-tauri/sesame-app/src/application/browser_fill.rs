use serde::Serialize;
use url::{Host, Url};

use crate::application::DesktopEffects;
use crate::browser_protocol::{CardFillFields, MAX_CREDENTIAL_FIELD_BYTES};
use crate::vault::imports::entry_from_input;
use crate::vault::storage::{commit_payload_change, payload_with_saved_login};
use crate::vault::util::unix_timestamp;
use crate::vault::{Card, LoginInput, SaveLoginResult, VaultEntry, VaultResult, VaultState};

use super::browser_fill_broker::BrowserFillState;

const APPROVAL_GONE: &str = "That browser approval is no longer available.";
const APPROVAL_EXPIRED: &str = "That browser approval expired or is no longer available.";
pub const APPROVAL_TOO_SOON: &str = "approvalTooSoon";
pub const APPROVAL_TOO_SOON_MESSAGE: &str =
    "Wait a moment after Sesame comes forward, then approve again.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedOrigin {
    scheme: &'static str,
    pub hostname: String,
    port: u16,
}

impl NormalizedOrigin {
    pub fn from_request(value: &str) -> Option<Self> {
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

    pub fn from_saved_url(value: &str) -> Option<Self> {
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

    pub fn canonical(&self) -> String {
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
pub enum OriginMatchKind {
    Exact,
    WwwAlias,
}

impl OriginMatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::WwwAlias => "wwwAlias",
        }
    }
}

pub fn origin_match_kind(
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
    pub id: String,
    pub title: String,
    pub username: String,
    /// Never crosses the pipe to the extension; only the desktop's own approval modal.
    pub email: String,
    pub saved_origin: String,
    #[ts(type = "'exact' | 'wwwAlias'")]
    pub match_kind: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardFillCandidate {
    pub id: String,
    title: String,
    brand: String,
    pub last_four: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFillRequestEvent {
    pub approval_id: String,
    pub origin: String,
    pub hostname: String,
    pub candidates: Vec<BrowserFillCandidate>,
    pub expires_in_seconds: u64,
    pub expires_at_unix_ms: u64,
}

/// Display-safe save prompt: the captured password never appears, and `candidates` are exact-origin targets for `update` only.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSaveRequestEvent {
    pub approval_id: String,
    pub origin: String,
    pub hostname: String,
    pub kind: &'static str,
    pub title: String,
    pub username: String,
    pub candidates: Vec<BrowserFillCandidate>,
    pub expires_in_seconds: u64,
    pub expires_at_unix_ms: u64,
}

/// Names only; identity values are read from the vault after the user picks.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityFillCandidate {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserIdentityRequestEvent {
    pub approval_id: String,
    pub origin: String,
    pub hostname: String,
    pub requested_fields: Vec<String>,
    pub candidates: Vec<IdentityFillCandidate>,
    pub expires_in_seconds: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserCardRequestEvent {
    pub approval_id: String,
    pub origin: String,
    pub hostname: String,
    pub requested_fields: Vec<String>,
    pub candidates: Vec<CardFillCandidate>,
    pub expires_in_seconds: u64,
    pub expires_at_unix_ms: u64,
}

/// Display fields only: neither the seed nor a derived code enters the prompt.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpFillCandidate {
    pub id: String,
    pub title: String,
    pub username: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserTotpRequestEvent {
    pub approval_id: String,
    pub origin: String,
    pub hostname: String,
    pub candidates: Vec<TotpFillCandidate>,
    pub expires_in_seconds: u64,
    pub expires_at_unix_ms: u64,
}

/// `new` versus `update`, decided by the extension from the page's own form structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveKind {
    New,
    Update,
}

impl SaveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Update => "update",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "new" => Some(Self::New),
            "update" => Some(Self::Update),
            _ => None,
        }
    }
}

pub enum ApprovalDecision {
    Denied,
    InvalidSelection,
    Selected(String),
    Saved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalKind {
    Fill,
    Save,
    Identity,
    Card,
    Totp,
}

impl ApprovalKind {
    pub fn cancelled_event(self) -> &'static str {
        match self {
            Self::Fill => "browser-fill-cancelled",
            Self::Save => "browser-save-cancelled",
            Self::Identity => "browser-identity-cancelled",
            Self::Card => "browser-card-cancelled",
            Self::Totp => "browser-totp-cancelled",
        }
    }

    pub fn timeout_code(self) -> &'static str {
        match self {
            Self::Fill => "fill_timeout",
            Self::Save => "save_timeout",
            Self::Identity => "identity_timeout",
            Self::Card => "card_timeout",
            Self::Totp => "totp_timeout",
        }
    }

    pub fn connection_closed_code(self) -> &'static str {
        match self {
            Self::Fill => "fill_connection_closed",
            Self::Save => "save_connection_closed",
            Self::Identity => "identity_connection_closed",
            Self::Card => "card_connection_closed",
            Self::Totp => "totp_connection_closed",
        }
    }

    pub fn vault_changed_code(self) -> &'static str {
        match self {
            Self::Fill => "fill_vault_changed",
            Self::Save => "save_vault_changed",
            Self::Identity => "identity_vault_changed",
            Self::Card => "card_vault_changed",
            Self::Totp => "totp_vault_changed",
        }
    }
}

/// Held credential, returned only while the approval is still bound.
pub struct SavePayload {
    pub kind: SaveKind,
    pub title: String,
    pub username: String,
    pub password: zeroize::Zeroizing<String>,
    pub origin: String,
    pub epoch: u64,
    pub candidates: Vec<BrowserFillCandidate>,
}

pub fn resolve_browser_fill_in_state(
    state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    approval_id: &str,
    login_id: Option<String>,
) -> VaultResult<()> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Err(APPROVAL_GONE.into());
    }
    let denied = login_id.is_none();
    let decision = login_id
        .map(ApprovalDecision::Selected)
        .unwrap_or(ApprovalDecision::Denied);
    match state.decide(approval_id, decision) {
        Ok(()) => {
            effects.record_browser_host_registration(if denied {
                "fill_denied"
            } else {
                "fill_approved"
            });
            if denied {
                effects.emit_browser_approval_cancelled(ApprovalKind::Fill, approval_id, "denied");
            }
            Ok(())
        }
        Err(error) => Err(rejected_decision(
            effects,
            ApprovalKind::Fill,
            approval_id,
            error,
        )),
    }
}

/// `update` changes only the password of a broker-found candidate; the caller can never name a login outside that set.
pub fn resolve_browser_save_in_state(
    state: &BrowserFillState,
    vault: &VaultState,
    effects: &dyn DesktopEffects,
    approval_id: &str,
    approved: bool,
    selected_id: Option<String>,
) -> VaultResult<Option<SaveLoginResult>> {
    if !approved {
        resolve_save(state, effects, approval_id, false)?;
        return Ok(None);
    }

    ensure_save_approval_ready(state, approval_id)?;

    let payload = save_payload(state, approval_id).ok_or(APPROVAL_EXPIRED)?;

    let save_result = match payload.kind {
        SaveKind::New => save_new_login(vault, payload),
        SaveKind::Update => save_login_update(vault, payload, selected_id),
    };

    match save_result {
        Ok(result) => {
            resolve_save(state, effects, approval_id, true)?;
            Ok(Some(result))
        }
        Err(error) => {
            // Release the broker so the extension is not left waiting.
            let _ = resolve_save(state, effects, approval_id, false);
            Err(error)
        }
    }
}

pub fn resolve_browser_identity_fill_in_state(
    state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    approval_id: &str,
    identity_id: Option<String>,
) -> VaultResult<()> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Err(APPROVAL_GONE.into());
    }
    let denied = identity_id.is_none();
    let decision = identity_id
        .map(ApprovalDecision::Selected)
        .unwrap_or(ApprovalDecision::Denied);
    match state.decide(approval_id, decision) {
        Ok(()) => {
            effects.record_browser_host_registration(if denied {
                "identity_denied"
            } else {
                "identity_approved"
            });
            if denied {
                effects.emit_browser_approval_cancelled(
                    ApprovalKind::Identity,
                    approval_id,
                    "denied",
                );
            }
            Ok(())
        }
        Err(error) => Err(rejected_decision(
            effects,
            ApprovalKind::Identity,
            approval_id,
            error,
        )),
    }
}

pub fn resolve_browser_card_fill_in_state(
    state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    approval_id: &str,
    card_id: Option<String>,
) -> VaultResult<()> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Err(APPROVAL_GONE.into());
    }
    let denied = card_id.is_none();
    let decision = card_id
        .map(ApprovalDecision::Selected)
        .unwrap_or(ApprovalDecision::Denied);
    match state.decide(approval_id, decision) {
        Ok(()) => {
            effects.record_browser_host_registration(if denied {
                "card_denied"
            } else {
                "card_approved"
            });
            if denied {
                effects.emit_browser_approval_cancelled(ApprovalKind::Card, approval_id, "denied");
            }
            Ok(())
        }
        Err(error) => Err(rejected_decision(
            effects,
            ApprovalKind::Card,
            approval_id,
            error,
        )),
    }
}

/// Every TOTP release needs its own approval; no grant is ever recorded.
pub fn resolve_browser_totp_fill_in_state(
    state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    approval_id: &str,
    login_id: Option<String>,
) -> VaultResult<()> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Err(APPROVAL_GONE.into());
    }
    let denied = login_id.is_none();
    let decision = login_id
        .map(ApprovalDecision::Selected)
        .unwrap_or(ApprovalDecision::Denied);
    match state.decide(approval_id, decision) {
        Ok(()) => {
            effects.record_browser_host_registration(if denied {
                "totp_denied"
            } else {
                "totp_approved"
            });
            if denied {
                effects.emit_browser_approval_cancelled(ApprovalKind::Totp, approval_id, "denied");
            }
            Ok(())
        }
        Err(error) => Err(rejected_decision(
            effects,
            ApprovalKind::Totp,
            approval_id,
            error,
        )),
    }
}

/// Releases the approval after the vault commit succeeds or is declined.
fn resolve_save(
    state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    approval_id: &str,
    approved: bool,
) -> VaultResult<()> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Err(APPROVAL_GONE.into());
    }
    let decision = if approved {
        ApprovalDecision::Saved
    } else {
        ApprovalDecision::Denied
    };
    match state.decide(approval_id, decision) {
        Ok(()) => {
            effects.record_browser_host_registration(if approved {
                "save_approved"
            } else {
                "save_denied"
            });
            if !approved {
                effects.emit_browser_approval_cancelled(ApprovalKind::Save, approval_id, "denied");
            }
            Ok(())
        }
        Err(error) => Err(rejected_decision(
            effects,
            ApprovalKind::Save,
            approval_id,
            error,
        )),
    }
}

/// The approval stays registered; the caller must finish with `resolve_save` either way.
fn save_payload(state: &BrowserFillState, approval_id: &str) -> Option<SavePayload> {
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

fn rejected_decision(
    effects: &dyn DesktopEffects,
    kind: ApprovalKind,
    approval_id: &str,
    error: &str,
) -> String {
    if error == APPROVAL_TOO_SOON {
        return APPROVAL_TOO_SOON_MESSAGE.to_string();
    }
    effects.emit_browser_approval_cancelled(kind, approval_id, "expired");
    APPROVAL_EXPIRED.to_string()
}

fn ensure_save_approval_ready(state: &BrowserFillState, approval_id: &str) -> VaultResult<()> {
    state.require_ready(approval_id).map_err(|error| {
        if error == APPROVAL_TOO_SOON {
            APPROVAL_TOO_SOON_MESSAGE.to_string()
        } else {
            APPROVAL_EXPIRED.to_string()
        }
    })
}

fn save_new_login(vault: &VaultState, payload: SavePayload) -> VaultResult<SaveLoginResult> {
    let input = LoginInput {
        urls: Vec::new(),
        tags: Vec::new(),
        id: None,
        title: payload.title,
        url: payload.origin,
        username: payload.username,
        email: String::new(),
        password: payload.password.to_string(),
        folder: String::new(),
        folder_id: None,
        totp: None,
        backup_codes: Vec::new(),
        keep_backup_codes: false,
        recovery_email: String::new(),
        recovery_phone: String::new(),
        recovery_not_applicable: false,
        notes: String::new(),
    };
    let entry = entry_from_input(input)?;
    let entry_id = entry.id.clone();
    let mut session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a login.".to_string())?;
    if vault.session_epoch() != payload.epoch {
        return Err(
            "The vault changed while this approval was open. Ask the browser to save again."
                .to_string(),
        );
    }
    let current = session.open_payload()?;
    let mut next_payload = current.clone();
    next_payload.entries.push(entry);
    commit_payload_change(session, next_payload)?;
    vault.advance_session_epoch();
    Ok(SaveLoginResult {
        id: entry_id,
        snapshot: session.snapshot(),
    })
}

/// Changes only the password; the outgoing value is captured to history first.
fn save_login_update(
    vault: &VaultState,
    payload: SavePayload,
    selected_id: Option<String>,
) -> VaultResult<SaveLoginResult> {
    let target_id = selected_id
        .filter(|id| {
            payload
                .candidates
                .iter()
                .any(|candidate| candidate.id == *id)
        })
        .ok_or_else(|| {
            "Choose which saved login this update belongs to before confirming.".to_string()
        })?;

    let mut session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a login.".to_string())?;
    if vault.session_epoch() != payload.epoch {
        return Err(
            "The vault changed while this approval was open. Ask the browser to save again."
                .to_string(),
        );
    }
    // Re-verified under the lock: still exactly this origin's saved login.
    let current = session.open_payload()?;
    if !verify_update_target(&current.entries, &payload.origin, &target_id) {
        return Err("That saved login no longer matches this site.".to_string());
    }

    let updated = current
        .entries
        .iter()
        .find(|entry| entry.id == target_id)
        .cloned()
        .ok_or("That saved login no longer exists.")?;
    let next_payload = payload_with_saved_login(
        &current,
        updated,
        Some(payload.password.to_string()),
        unix_timestamp(),
    )?;
    commit_payload_change(session, next_payload)?;
    vault.advance_session_epoch();
    Ok(SaveLoginResult {
        id: target_id,
        snapshot: session.snapshot(),
    })
}

pub fn card_candidate(card: &Card) -> CardFillCandidate {
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

pub fn card_supports_fields(card: &Card, requested: &[String]) -> bool {
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

pub fn selected_card_fields(card: &Card, requested: &[String]) -> CardFillFields {
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

pub fn bounded_display(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}
