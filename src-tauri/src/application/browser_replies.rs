use std::{
    collections::HashSet,
    sync::mpsc::Receiver,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use unicode_security::mixed_script::AugmentedScriptSet;
use url::Host;

use crate::application::DesktopEffects;
use crate::browser_protocol::{
    fill_carries_match_kind, parse_card_fields, parse_identity_fields, BrowserRequest,
    BrowserResponse, IdentityFillFields, LOOKALIKE_PROTOCOL_VERSION, MAX_CREDENTIAL_FIELD_BYTES,
    MAX_LOOKALIKE_HOST_CHARS,
};
use crate::vault::snapshot::{current_totp, totp_from_value};
use crate::vault::{Identity, TaggedItem, VaultEntry, VaultState};

use super::browser_fill::{
    bounded_display, card_candidate, card_supports_fields, origin_match_kind, selected_card_fields,
    ApprovalDecision, ApprovalKind, BrowserCardRequestEvent, BrowserFillCandidate,
    BrowserFillRequestEvent, BrowserIdentityRequestEvent, BrowserSaveRequestEvent,
    BrowserTotpRequestEvent, IdentityFillCandidate, NormalizedOrigin, OriginMatchKind, SaveKind,
    TotpFillCandidate,
};
use super::browser_fill_broker::{
    ApprovalEvent, ApprovalRequest, BrowserFillState, APPROVAL_TIMEOUT,
};

pub(super) const MAX_MATCHING_CANDIDATES: usize = 32;

pub(crate) struct BrowserApproval {
    pub(crate) approval_id: String,
    pub(crate) origin: NormalizedOrigin,
    pub(crate) epoch: u64,
    pub(crate) kind: ApprovalKind,
    pub(crate) event: ApprovalEvent,
    pub(crate) requested_fields: Vec<String>,
}

pub(crate) struct BrowserApprovalOffer {
    pub(crate) approval: BrowserApproval,
    pub(crate) deadline: Instant,
    pub(crate) receiver: Receiver<ApprovalDecision>,
}

pub(crate) enum BrowserReply {
    Response(Box<BrowserResponse>),
    Approval(Box<BrowserApprovalOffer>),
}

impl From<BrowserResponse> for BrowserReply {
    fn from(response: BrowserResponse) -> Self {
        Self::Response(Box::new(response))
    }
}

impl From<BrowserApprovalOffer> for BrowserReply {
    fn from(offer: BrowserApprovalOffer) -> Self {
        Self::Approval(Box::new(offer))
    }
}

pub(crate) struct ActivationReply {
    pub(crate) response: BrowserResponse,
    pub(crate) show_window: bool,
}

pub(crate) fn capabilities_response(request: &BrowserRequest) -> BrowserResponse {
    BrowserResponse::capabilities(&request.request_id, true)
}

pub(crate) fn activation_response_in_state(
    fill_state: &BrowserFillState,
    request: &BrowserRequest,
    now: Instant,
) -> ActivationReply {
    if !fill_state.note_activation(now) {
        return ActivationReply {
            response: BrowserResponse::activated(&request.request_id, false),
            show_window: false,
        };
    }
    ActivationReply {
        response: BrowserResponse::activated(&request.request_id, true),
        show_window: true,
    }
}

pub(crate) fn fill_response_in_state(
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
) -> BrowserReply {
    effects.record_browser_host_registration("fill_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::unavailable(request, "staleRequest").into();
    };
    let (epoch, candidates, lookalike) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => {
                return BrowserResponse::unavailable(request, "approvalUnavailable").into();
            }
        };
        let Some(session) = session.as_ref() else {
            effects.record_browser_host_registration("fill_locked");
            return BrowserResponse::unavailable(request, "noMatch").into();
        };
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => {
                return BrowserResponse::unavailable(request, "approvalUnavailable").into();
            }
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
            return BrowserResponse::lookalike_unavailable(request, lookalike).into();
        }
        effects.record_browser_host_registration("fill_no_match");
        return BrowserResponse::unavailable(request, "noMatch").into();
    }
    if candidates.len() > MAX_MATCHING_CANDIDATES {
        return BrowserResponse::unavailable(request, "noMatch").into();
    }

    let candidate_ids: HashSet<String> = candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let (approval_id, deadline, receiver) = match fill_state.begin(
        &request.request_id,
        origin.clone(),
        epoch,
        ApprovalRequest::Fill { candidate_ids },
    ) {
        Ok(value) => value,
        Err(reason) => return BrowserResponse::unavailable(request, reason).into(),
    };

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
        return BrowserResponse::unavailable(request, "approvalUnavailable").into();
    }
    BrowserApprovalOffer {
        approval: BrowserApproval {
            approval_id,
            origin,
            epoch,
            kind: ApprovalKind::Fill,
            event: ApprovalEvent::Fill(event),
            requested_fields: Vec::new(),
        },
        deadline,
        receiver,
    }
    .into()
}

pub(crate) fn complete_fill_in_state(
    vault: &VaultState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
    approval: &BrowserApproval,
    decision: ApprovalDecision,
    peer_connected: bool,
) -> BrowserResponse {
    let login_id = match decision {
        ApprovalDecision::Selected(login_id) => login_id,
        ApprovalDecision::Denied => {
            return BrowserResponse::unavailable(request, "approvalDeclined")
        }
        ApprovalDecision::InvalidSelection | ApprovalDecision::Saved => {
            return BrowserResponse::unavailable(request, "invalidSelection")
        }
    };
    if !peer_connected {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Fill,
            &approval.approval_id,
            "connectionClosed",
        );
        return BrowserResponse::unavailable(request, "staleRequest");
    }

    // Bindings rechecked after approval under the vault lock; no credential is copied before this.
    let session = match vault.session.lock() {
        Ok(session) => session,
        Err(_) => return BrowserResponse::unavailable(request, "approvalUnavailable"),
    };
    if vault.session_epoch() != approval.epoch {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Fill,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::unavailable(request, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Fill,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::unavailable(request, "locked");
    };
    let Ok(item) = session.open_item(&login_id) else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Fill,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::unavailable(request, "staleRequest");
    };
    let TaggedItem::Login(entry) = &*item else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Fill,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::unavailable(request, "staleRequest");
    };
    let Some(match_kind) = NormalizedOrigin::from_saved_url(&entry.url)
        .as_ref()
        .and_then(|saved| origin_match_kind(saved, &approval.origin))
    else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Fill,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::unavailable(request, "staleRequest");
    };
    if !credential_fields_valid(entry) {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Fill,
            &approval.approval_id,
            "vaultChanged",
        );
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

pub(crate) fn save_response_in_state(
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &mut BrowserRequest,
) -> BrowserReply {
    effects.record_browser_host_registration("save_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::save_unavailable(&request.request_id, "staleRequest").into();
    };
    let Some(kind) = request.kind.as_deref().and_then(SaveKind::parse) else {
        return BrowserResponse::save_unavailable(&request.request_id, "staleRequest").into();
    };

    let (epoch, candidates) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => {
                return BrowserResponse::save_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
                .into()
            }
        };
        let Some(session) = session.as_ref() else {
            effects.record_browser_host_registration("save_locked");
            return BrowserResponse::save_unavailable(&request.request_id, "noMatch").into();
        };
        // `update` candidates come from the vault, never from the extension.
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => {
                return BrowserResponse::save_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
                .into()
            }
        };
        let candidates = match kind {
            SaveKind::New => Vec::new(),
            SaveKind::Update => matching_entries(&payload.entries, &origin),
        };
        (vault.session_epoch(), candidates)
    };
    if kind == SaveKind::Update && candidates.is_empty() {
        effects.record_browser_host_registration("save_update_no_match");
        return BrowserResponse::save_unavailable(&request.request_id, "noMatch").into();
    }
    if candidates.len() > MAX_MATCHING_CANDIDATES {
        return BrowserResponse::save_unavailable(&request.request_id, "noMatch").into();
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

    let (approval_id, deadline, receiver) = match fill_state.begin(
        &request.request_id,
        origin.clone(),
        epoch,
        ApprovalRequest::Save {
            kind,
            title: title.clone(),
            username: username.clone(),
            password,
            candidates: candidates.clone(),
        },
    ) {
        Ok(value) => value,
        Err(reason) => {
            return BrowserResponse::save_unavailable(&request.request_id, reason).into()
        }
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
        return BrowserResponse::save_unavailable(&request.request_id, "approvalUnavailable")
            .into();
    }
    BrowserApprovalOffer {
        approval: BrowserApproval {
            approval_id,
            origin,
            epoch,
            kind: ApprovalKind::Save,
            event: ApprovalEvent::Save(event),
            requested_fields: Vec::new(),
        },
        deadline,
        receiver,
    }
    .into()
}

pub(crate) fn complete_save_in_state(
    request: &BrowserRequest,
    decision: ApprovalDecision,
) -> BrowserResponse {
    match decision {
        ApprovalDecision::Saved => BrowserResponse::saved(&request.request_id),
        ApprovalDecision::Denied => {
            BrowserResponse::save_unavailable(&request.request_id, "approvalDeclined")
        }
        _ => BrowserResponse::save_unavailable(&request.request_id, "invalidSelection"),
    }
}

pub(crate) fn card_response_in_state(
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
) -> BrowserReply {
    effects.record_browser_host_registration("card_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest").into();
    };
    let Some(requested_fields) = request.fields.as_deref().and_then(parse_card_fields) else {
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest").into();
    };
    let (epoch, candidates) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => {
                return BrowserResponse::card_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
                .into()
            }
        };
        let Some(session) = session.as_ref() else {
            effects.record_browser_host_registration("card_locked");
            return BrowserResponse::card_unavailable(&request.request_id, "noMatch").into();
        };
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => {
                return BrowserResponse::card_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
                .into()
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
        effects.record_browser_host_registration("card_no_match");
        return BrowserResponse::card_unavailable(&request.request_id, "noMatch").into();
    }
    let candidate_ids = candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let (approval_id, deadline, receiver) = match fill_state.begin(
        &request.request_id,
        origin.clone(),
        epoch,
        ApprovalRequest::Card { candidate_ids },
    ) {
        Ok(value) => value,
        Err(reason) => {
            return BrowserResponse::card_unavailable(&request.request_id, reason).into()
        }
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
        return BrowserResponse::card_unavailable(&request.request_id, "approvalUnavailable")
            .into();
    }
    BrowserApprovalOffer {
        approval: BrowserApproval {
            approval_id,
            origin,
            epoch,
            kind: ApprovalKind::Card,
            event: ApprovalEvent::Card(event),
            requested_fields,
        },
        deadline,
        receiver,
    }
    .into()
}

pub(crate) fn complete_card_in_state(
    vault: &VaultState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
    approval: &BrowserApproval,
    decision: ApprovalDecision,
    peer_connected: bool,
) -> BrowserResponse {
    let requested_fields = &approval.requested_fields;
    let card_id = match decision {
        ApprovalDecision::Selected(card_id) => card_id,
        ApprovalDecision::Denied => {
            return BrowserResponse::card_unavailable(&request.request_id, "approvalDeclined")
        }
        ApprovalDecision::InvalidSelection | ApprovalDecision::Saved => {
            return BrowserResponse::card_unavailable(&request.request_id, "invalidSelection")
        }
    };
    if !peer_connected {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Card,
            &approval.approval_id,
            "connectionClosed",
        );
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    }
    let session = match vault.session.lock() {
        Ok(session) => session,
        Err(_) => {
            return BrowserResponse::card_unavailable(&request.request_id, "approvalUnavailable")
        }
    };
    if vault.session_epoch() != approval.epoch {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Card,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Card,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::card_unavailable(&request.request_id, "locked");
    };
    let Ok(item) = session.open_item(&card_id) else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Card,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    };
    let TaggedItem::Card(card) = &*item else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Card,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    };
    if !card_supports_fields(card, requested_fields) {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Card,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    }
    BrowserResponse::card_for(request, selected_card_fields(card, requested_fields))
}

pub(crate) fn identity_response_in_state(
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
) -> BrowserReply {
    effects.record_browser_host_registration("identity_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest").into();
    };
    let Some(requested_fields) = request.fields.as_deref().and_then(parse_identity_fields) else {
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest").into();
    };

    let (epoch, candidates) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => {
                return BrowserResponse::identity_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
                .into()
            }
        };
        let Some(session) = session.as_ref() else {
            effects.record_browser_host_registration("identity_locked");
            return BrowserResponse::identity_unavailable(&request.request_id, "noMatch").into();
        };
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => {
                return BrowserResponse::identity_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
                .into()
            }
        };
        let candidates: Vec<IdentityFillCandidate> = payload
            .identities
            .iter()
            .take(MAX_MATCHING_CANDIDATES)
            .map(|identity| IdentityFillCandidate {
                id: identity.id.clone(),
                label: bounded_display(&identity.label, 128),
            })
            .collect();
        (vault.session_epoch(), candidates)
    };
    if candidates.is_empty() {
        effects.record_browser_host_registration("identity_no_match");
        return BrowserResponse::identity_unavailable(&request.request_id, "noMatch").into();
    }

    let candidate_ids = candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let (approval_id, deadline, receiver) = match fill_state.begin(
        &request.request_id,
        origin.clone(),
        epoch,
        ApprovalRequest::Identity { candidate_ids },
    ) {
        Ok(value) => value,
        Err(reason) => {
            return BrowserResponse::identity_unavailable(&request.request_id, reason).into()
        }
    };

    let event = BrowserIdentityRequestEvent {
        approval_id: approval_id.clone(),
        origin: origin.canonical(),
        hostname: origin.hostname.clone(),
        requested_fields: requested_fields.clone(),
        candidates,
        expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
        expires_at_unix_ms: approval_expires_at_unix_ms(),
    };
    if fill_state
        .publish(&approval_id, ApprovalEvent::Identity(event.clone()))
        .is_err()
    {
        fill_state.revoke(&approval_id);
        return BrowserResponse::identity_unavailable(&request.request_id, "approvalUnavailable")
            .into();
    }
    BrowserApprovalOffer {
        approval: BrowserApproval {
            approval_id,
            origin,
            epoch,
            kind: ApprovalKind::Identity,
            event: ApprovalEvent::Identity(event),
            requested_fields,
        },
        deadline,
        receiver,
    }
    .into()
}

pub(crate) fn complete_identity_in_state(
    vault: &VaultState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
    approval: &BrowserApproval,
    decision: ApprovalDecision,
    peer_connected: bool,
) -> BrowserResponse {
    let requested_fields = &approval.requested_fields;
    let identity_id = match decision {
        ApprovalDecision::Selected(identity_id) => identity_id,
        ApprovalDecision::Denied => {
            return BrowserResponse::identity_unavailable(&request.request_id, "approvalDeclined")
        }
        ApprovalDecision::InvalidSelection | ApprovalDecision::Saved => {
            return BrowserResponse::identity_unavailable(&request.request_id, "invalidSelection")
        }
    };
    if !peer_connected {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Identity,
            &approval.approval_id,
            "connectionClosed",
        );
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    }

    // Recheck under the current vault lock. No identity value is read before this point.
    let session = match vault.session.lock() {
        Ok(session) => session,
        Err(_) => {
            return BrowserResponse::identity_unavailable(
                &request.request_id,
                "approvalUnavailable",
            )
        }
    };
    if vault.session_epoch() != approval.epoch {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Identity,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Identity,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::identity_unavailable(&request.request_id, "locked");
    };
    let Ok(item) = session.open_item(&identity_id) else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Identity,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    };
    let TaggedItem::Identity(identity) = &*item else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Identity,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    };
    BrowserResponse::identity_for(
        request,
        selected_identity_fields(identity, requested_fields),
    )
}

fn selected_identity_fields(identity: &Identity, requested: &[String]) -> IdentityFillFields {
    let mut fields = IdentityFillFields::default();
    for key in requested {
        match key.as_str() {
            "fullName" => fields.full_name = Some(bounded_display(&identity.full_name, 256)),
            "email" => fields.email = Some(bounded_display(&identity.email, 320)),
            "phone" => fields.phone = Some(bounded_display(&identity.phone, 64)),
            "addressLine1" => {
                fields.address_line1 = Some(bounded_display(&identity.address_line1, 256))
            }
            "addressLine2" => {
                fields.address_line2 = Some(bounded_display(&identity.address_line2, 256))
            }
            "city" => fields.city = Some(bounded_display(&identity.city, 128)),
            "region" => fields.region = Some(bounded_display(&identity.region, 128)),
            "postalCode" => fields.postal_code = Some(bounded_display(&identity.postal_code, 32)),
            "country" => fields.country = Some(bounded_display(&identity.country, 128)),
            _ => {}
        }
    }
    fields
}

pub(crate) fn totp_response_in_state(
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
) -> BrowserReply {
    effects.record_browser_host_registration("totp_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest").into();
    };
    let (epoch, candidates) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => {
                return BrowserResponse::totp_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
                .into()
            }
        };
        let Some(session) = session.as_ref() else {
            effects.record_browser_host_registration("totp_locked");
            return BrowserResponse::totp_unavailable(&request.request_id, "noMatch").into();
        };
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => {
                return BrowserResponse::totp_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
                .into()
            }
        };
        (
            vault.session_epoch(),
            matching_totp_entries(&payload.entries, &origin),
        )
    };
    if candidates.is_empty() {
        effects.record_browser_host_registration("totp_no_match");
        return BrowserResponse::totp_unavailable(&request.request_id, "noMatch").into();
    }

    let candidate_ids = candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let (approval_id, deadline, receiver) = match fill_state.begin(
        &request.request_id,
        origin.clone(),
        epoch,
        ApprovalRequest::Totp { candidate_ids },
    ) {
        Ok(value) => value,
        Err(reason) => {
            return BrowserResponse::totp_unavailable(&request.request_id, reason).into()
        }
    };
    let event = BrowserTotpRequestEvent {
        approval_id: approval_id.clone(),
        origin: origin.canonical(),
        hostname: origin.hostname.clone(),
        candidates,
        expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
        expires_at_unix_ms: approval_expires_at_unix_ms(),
    };
    if fill_state
        .publish(&approval_id, ApprovalEvent::Totp(event.clone()))
        .is_err()
    {
        fill_state.revoke(&approval_id);
        return BrowserResponse::totp_unavailable(&request.request_id, "approvalUnavailable")
            .into();
    }
    BrowserApprovalOffer {
        approval: BrowserApproval {
            approval_id,
            origin,
            epoch,
            kind: ApprovalKind::Totp,
            event: ApprovalEvent::Totp(event),
            requested_fields: Vec::new(),
        },
        deadline,
        receiver,
    }
    .into()
}

pub(crate) fn complete_totp_in_state(
    vault: &VaultState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
    approval: &BrowserApproval,
    decision: ApprovalDecision,
    peer_connected: bool,
) -> BrowserResponse {
    let login_id = match decision {
        ApprovalDecision::Selected(login_id) => login_id,
        ApprovalDecision::Denied => {
            return BrowserResponse::totp_unavailable(&request.request_id, "approvalDeclined")
        }
        ApprovalDecision::InvalidSelection | ApprovalDecision::Saved => {
            return BrowserResponse::totp_unavailable(&request.request_id, "invalidSelection")
        }
    };
    if !peer_connected {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Totp,
            &approval.approval_id,
            "connectionClosed",
        );
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    }

    let session = match vault.session.lock() {
        Ok(session) => session,
        Err(_) => {
            return BrowserResponse::totp_unavailable(&request.request_id, "approvalUnavailable")
        }
    };
    if vault.session_epoch() != approval.epoch {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Totp,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Totp,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::totp_unavailable(&request.request_id, "locked");
    };
    let Ok(item) = session.open_item(&login_id) else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Totp,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    };
    let TaggedItem::Login(entry) = &*item else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Totp,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    };
    let Some(saved_origin) = NormalizedOrigin::from_saved_url(&entry.url) else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Totp,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    };
    if origin_match_kind(&saved_origin, &approval.origin).is_none() {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Totp,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    }
    let Some(response) = entry
        .totp
        .as_deref()
        .and_then(|secret| totp_response_for_secret(request, secret))
    else {
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Totp,
            &approval.approval_id,
            "vaultChanged",
        );
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    };
    response
}

pub(super) fn totp_response_for_secret(
    request: &BrowserRequest,
    secret: &str,
) -> Option<BrowserResponse> {
    let (code, remaining, _period) = current_totp(secret)?;
    let response = BrowserResponse::totp_for(request, code, remaining);
    response.validate_for(request).then_some(response)
}

pub(super) fn matching_entries(
    entries: &[VaultEntry],
    origin: &NormalizedOrigin,
) -> Vec<BrowserFillCandidate> {
    let mut candidates = Vec::new();
    for requested_kind in [OriginMatchKind::Exact, OriginMatchKind::WwwAlias] {
        for entry in entries {
            if !credential_fields_valid(entry) {
                continue;
            }
            let Some(saved_origin) = NormalizedOrigin::from_saved_url(&entry.url) else {
                continue;
            };
            if origin_match_kind(&saved_origin, origin) != Some(requested_kind) {
                continue;
            }
            candidates.push(BrowserFillCandidate {
                id: entry.id.clone(),
                title: bounded_display(&entry.title, 128),
                username: bounded_display(&entry.username, 256),
                email: bounded_display(&entry.email, 256),
                saved_origin: saved_origin.canonical(),
                match_kind: requested_kind.as_str(),
            });
            if candidates.len() >= MAX_MATCHING_CANDIDATES {
                return candidates;
            }
        }
    }
    candidates
}

fn credential_fields_valid(entry: &VaultEntry) -> bool {
    entry.username.len() <= MAX_CREDENTIAL_FIELD_BYTES
        && !entry.password.is_empty()
        && entry.password.len() <= MAX_CREDENTIAL_FIELD_BYTES
}

fn totp_fields_valid(entry: &VaultEntry) -> bool {
    entry
        .totp
        .as_deref()
        .is_some_and(|seed| totp_from_value(seed).is_some())
}

pub(super) fn matching_totp_entries(
    entries: &[VaultEntry],
    origin: &NormalizedOrigin,
) -> Vec<TotpFillCandidate> {
    let mut candidates = Vec::new();
    for requested_kind in [OriginMatchKind::Exact, OriginMatchKind::WwwAlias] {
        for entry in entries {
            if !totp_fields_valid(entry) {
                continue;
            }
            let Some(saved_origin) = NormalizedOrigin::from_saved_url(&entry.url) else {
                continue;
            };
            if origin_match_kind(&saved_origin, origin) != Some(requested_kind) {
                continue;
            }
            candidates.push(TotpFillCandidate {
                id: entry.id.clone(),
                title: bounded_display(&entry.title, 128),
                username: bounded_display(&entry.username, 256),
            });
            if candidates.len() >= MAX_MATCHING_CANDIDATES {
                return candidates;
            }
        }
    }
    candidates
}

pub(super) fn lookalike_host(
    entries: &[VaultEntry],
    requested: &NormalizedOrigin,
) -> Option<String> {
    let requested_registrable = registrable_domain(&requested.hostname)?;
    let requested_unicode = decode_domain(requested_registrable)?;
    let requested_skeleton = confusable_skeleton(&requested_unicode);
    let requested_mixed_script = has_confusable_mixed_script_label(&requested_unicode);
    for entry in entries {
        let Some(saved_origin) = NormalizedOrigin::from_saved_url(&entry.url) else {
            continue;
        };
        if saved_origin.hostname == requested.hostname {
            continue;
        }
        let Some(saved_registrable) = registrable_domain(&saved_origin.hostname) else {
            continue;
        };
        if saved_registrable == requested_registrable {
            continue;
        }
        let Some(saved_unicode) = decode_domain(saved_registrable) else {
            continue;
        };
        if saved_unicode == requested_unicode {
            continue;
        }
        let saved_skeleton = confusable_skeleton(&saved_unicode);
        if requested_skeleton == saved_skeleton {
            return Some(bounded_lookalike_host(&saved_origin.hostname));
        }
        let budget = edit_budget(
            requested_skeleton
                .chars()
                .count()
                .max(saved_skeleton.chars().count()),
        );
        if budget == 0 {
            continue;
        }
        let within_budget = within_edit_distance(&requested_skeleton, &saved_skeleton, budget);
        if within_budget
            && (requested_mixed_script
                || first_and_last_match(&requested_skeleton, &saved_skeleton))
        {
            return Some(bounded_lookalike_host(&saved_origin.hostname));
        }
    }
    None
}

fn registrable_domain(hostname: &str) -> Option<&str> {
    if !hostname.contains('.') || hostname.contains(':') {
        return None;
    }
    match Host::parse(hostname) {
        Ok(Host::Domain(domain)) if domain == hostname => psl::domain_str(hostname),
        _ => None,
    }
}

fn decode_domain(domain: &str) -> Option<String> {
    let (decoded, result) = idna::domain_to_unicode(domain);
    result.ok()?;
    (!decoded.is_empty()).then_some(decoded)
}

pub(super) fn confusable_skeleton(domain: &str) -> String {
    unicode_security::skeleton(domain).collect()
}

fn has_confusable_mixed_script_label(domain: &str) -> bool {
    const CONFUSABLE_PROBES: [char; 4] = ['\u{0430}', '\u{03b1}', '\u{0561}', '\u{13a0}'];
    domain.split('.').any(|label| {
        let mut has_latin = false;
        let mut has_confusable_pair = false;
        for value in label.chars() {
            let script_set = AugmentedScriptSet::for_char(value);
            if script_set.is_all() {
                continue;
            }
            if shares_script(script_set, 'a') {
                has_latin = true;
            }
            if CONFUSABLE_PROBES
                .iter()
                .any(|probe| shares_script(script_set, *probe))
            {
                has_confusable_pair = true;
            }
        }
        has_latin && has_confusable_pair
    })
}

fn shares_script(script_set: AugmentedScriptSet, probe: char) -> bool {
    let mut combined = script_set;
    combined.intersect_with(AugmentedScriptSet::for_char(probe));
    !combined.is_empty()
}

fn bounded_lookalike_host(hostname: &str) -> String {
    bounded_display(hostname, MAX_LOOKALIKE_HOST_CHARS)
        .trim_end_matches('.')
        .to_string()
}

fn edit_budget(length: usize) -> usize {
    if length >= 16 {
        2
    } else if length >= 8 {
        1
    } else {
        0
    }
}

fn first_and_last_match(left: &str, right: &str) -> bool {
    left.chars().next().is_some()
        && left.chars().next() == right.chars().next()
        && left.chars().last() == right.chars().last()
}

fn within_edit_distance(left: &str, right: &str, max: usize) -> bool {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    let (rows, columns) = (left.len(), right.len());
    if rows.abs_diff(columns) > max {
        return false;
    }
    let unreachable = max + 1;
    let mut previous = vec![unreachable; columns + 1];
    for (column, value) in previous.iter_mut().enumerate() {
        if column <= max {
            *value = column;
        }
    }
    let mut current = vec![unreachable; columns + 1];
    for row in 1..=rows {
        current.fill(unreachable);
        let low = row.saturating_sub(max);
        let high = (row + max).min(columns);
        let mut row_min = unreachable;
        for column in low..=high {
            let distance = if column == 0 {
                previous[0].saturating_add(1)
            } else {
                let substitution =
                    previous[column - 1] + usize::from(left[row - 1] != right[column - 1]);
                let deletion = previous[column].saturating_add(1);
                let insertion = current[column - 1].saturating_add(1);
                substitution.min(deletion).min(insertion)
            }
            .min(unreachable);
            current[column] = distance;
            row_min = row_min.min(distance);
        }
        if row_min > max {
            return false;
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[columns] <= max
}

fn approval_expires_at_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(APPROVAL_TIMEOUT)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
