use std::collections::HashSet;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::application::DesktopEffects;
use crate::browser_protocol::{BrowserRequest, BrowserResponse};
use crate::vault::generator::{generate_password, PasswordStyle};
use crate::vault::history::HISTORY_RETENTION_SECONDS;
use crate::vault::imports::entry_from_input;
use crate::vault::pending_change::{
    find_by_handle, has_room, issue_handle, prune, read_pending, write_pending, FillState,
    PendingChange, PendingKind, Resolution, ESCALATE_AFTER_SECS,
};
use crate::vault::release_record::{MatchKind, Outcome};
use crate::vault::storage::{commit_payload_change, payload_with_saved_login};
use crate::vault::trash::trash_item;
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{
    LoginInput, TaggedItem, UnlockedVault, VaultPayload, VaultResult, VaultSnapshot, VaultState,
};

use super::browser_fill::{
    bounded_display, login_match, never_saves, ApprovalDecision, ApprovalKind,
    BrowserChangeRequestEvent, BrowserCreateRequestEvent, NormalizedOrigin,
};
use super::browser_fill_broker::{
    ApprovalEvent, ApprovalRequest, BrowserFillState, APPROVAL_TIMEOUT,
};
use super::browser_replies::{
    approval_expires_at_unix_ms, begin_refusal, credential_fields_valid, lookalike_host,
    matching_entries, note, refused, register_approval, BrowserApproval, BrowserReply,
    RegisterError, MAX_MATCHING_CANDIDATES,
};
use super::release_record::{browser_draft, record, record_in};

const MAX_USERNAME_CHARS: usize = 2048;
const DAY_SECS: u64 = 86_400;
const NO_LONGER_WAITING: &str = "This password is no longer waiting.";
const UNLOCK_FIRST: &str = "Unlock Sesame first.";

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct PendingChangeView {
    pub id: String,
    pub item_id: String,
    pub kind: PendingKind,
    pub host: String,
    pub title: String,
    pub username: String,
    pub created_at: u64,
    pub fill: FillState,
    pub accepted: bool,
    pub can_go_back: bool,
    pub superseded: bool,
    pub days_left: Option<u32>,
    pub urgent: bool,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct PendingChangeList {
    pub changes: Vec<PendingChangeView>,
    pub snapshot: Option<VaultSnapshot>,
}

fn style_of(request: &BrowserRequest) -> Option<PasswordStyle> {
    PasswordStyle::parse(request.style.as_deref()?, request.size?)
}

fn unavailable(request: &BrowserRequest, reason: &'static str) -> BrowserResponse {
    BrowserResponse::operation_unavailable(request, reason)
}

fn unresolved_items(session: &UnlockedVault) -> HashSet<String> {
    read_pending(session)
        .unwrap_or_default()
        .into_iter()
        .filter(PendingChange::is_unresolved)
        .map(|change| change.item_id)
        .collect()
}

pub fn change_response_in_state(
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
) -> BrowserReply {
    effects.record_browser_host_registration("change_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return unavailable(request, "staleRequest").into();
    };
    if style_of(request).is_none() {
        return unavailable(request, "staleRequest").into();
    }
    let (epoch, candidates, lookalike, waiting) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => return unavailable(request, "approvalUnavailable").into(),
        };
        let Some(session) = session.as_ref() else {
            effects.record_browser_host_registration("change_locked");
            vault.release_record.append_locked(browser_draft(
                ApprovalKind::Change,
                Outcome::Locked,
                &origin.hostname,
            ));
            return unavailable(request, "locked").into();
        };
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => return unavailable(request, "approvalUnavailable").into(),
        };
        if never_saves(&payload.never_save_sites, &origin) {
            effects.record_browser_host_registration("change_never_site");
            record_in(
                vault,
                Some(session),
                browser_draft(ApprovalKind::Change, Outcome::NeverSave, &origin.hostname),
            );
            return unavailable(request, "approvalDeclined").into();
        }
        let candidates = matching_entries(&payload.entries, &origin, true);
        let only_site_candidates = candidates
            .iter()
            .all(|candidate| candidate.match_kind == "site");
        let lookalike = if only_site_candidates {
            lookalike_host(&payload.entries, &origin)
        } else {
            None
        };
        let waiting = unresolved_items(session);
        (vault.session_epoch(), candidates, lookalike, waiting)
    };
    if let Some(lookalike) = lookalike {
        record(
            vault,
            browser_draft(ApprovalKind::Change, Outcome::Lookalike, &origin.hostname)
                .similar_to(&lookalike),
        );
        return BrowserResponse::change_lookalike_unavailable(request, lookalike).into();
    }
    if candidates.is_empty() || candidates.len() > MAX_MATCHING_CANDIDATES {
        effects.record_browser_host_registration("change_no_match");
        refused(vault, ApprovalKind::Change, &origin, Outcome::NoMatch);
        return unavailable(request, "noMatch").into();
    }
    let candidate_ids: HashSet<String> = candidates.iter().map(|item| item.id.clone()).collect();
    let unconfirmed = candidates
        .iter()
        .filter(|candidate| waiting.contains(&candidate.id))
        .map(|candidate| candidate.id.clone())
        .collect();
    let hostname = origin.hostname.clone();
    let canonical = origin.canonical();
    match register_approval(
        fill_state,
        &request.request_id,
        origin.clone(),
        epoch,
        ApprovalKind::Change,
        ApprovalRequest::Change { candidate_ids },
        |approval_id| {
            ApprovalEvent::Change(BrowserChangeRequestEvent {
                approval_id: approval_id.to_string(),
                origin: canonical,
                hostname,
                candidates,
                unconfirmed,
                expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
                expires_at_unix_ms: approval_expires_at_unix_ms(),
            })
        },
    ) {
        Ok(offer) => offer.into(),
        Err(RegisterError::Begin(reason)) => {
            refused(vault, ApprovalKind::Change, &origin, begin_refusal(reason));
            unavailable(request, reason).into()
        }
        Err(RegisterError::Publish) => unavailable(request, "approvalUnavailable").into(),
    }
}

fn stale(
    vault: &VaultState,
    effects: &dyn DesktopEffects,
    approval: &BrowserApproval,
    session: Option<&UnlockedVault>,
    item_id: Option<&str>,
) {
    let mut draft = approval.draft(Outcome::VaultChanged);
    if let Some(item_id) = item_id {
        draft = draft.item(item_id, "login");
    }
    note(vault, session, draft);
    effects.emit_browser_approval_cancelled(
        approval.kind(),
        approval.approval_id(),
        "vaultChanged",
    );
}

pub fn complete_change_in_state(
    vault: &VaultState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
    approval: &BrowserApproval,
    decision: ApprovalDecision,
    peer_connected: &dyn Fn() -> bool,
) -> BrowserResponse {
    let login_id = match decision {
        ApprovalDecision::Selected(login_id) => login_id,
        ApprovalDecision::Denied => return unavailable(request, "approvalDeclined"),
        _ => return unavailable(request, "invalidSelection"),
    };
    if !peer_connected() {
        record(
            vault,
            approval
                .draft(Outcome::ConnectionClosed)
                .item(&login_id, "login"),
        );
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Change,
            approval.approval_id(),
            "connectionClosed",
        );
        return unavailable(request, "staleRequest");
    }
    let Some(style) = style_of(request) else {
        return unavailable(request, "staleRequest");
    };
    let mut guard = match vault.session.lock() {
        Ok(guard) => guard,
        Err(_) => return unavailable(request, "approvalUnavailable"),
    };
    if vault.session_epoch() != approval.epoch() {
        stale(vault, effects, approval, guard.as_ref(), Some(&login_id));
        return unavailable(request, "staleRequest");
    }
    let Some(session) = guard.as_mut() else {
        stale(vault, effects, approval, None, Some(&login_id));
        return unavailable(request, "locked");
    };
    let Ok(payload) = session.open_payload() else {
        return unavailable(request, "approvalUnavailable");
    };
    if never_saves(&payload.never_save_sites, approval.origin()) {
        note(
            vault,
            Some(session),
            approval.draft(Outcome::NeverSave).item(&login_id, "login"),
        );
        return unavailable(request, "approvalDeclined");
    }
    let Some(entry) = payload
        .entries
        .iter()
        .find(|entry| entry.id == login_id)
        .cloned()
    else {
        stale(vault, effects, approval, Some(session), Some(&login_id));
        return unavailable(request, "staleRequest");
    };
    let Some((match_kind, _)) = login_match(&entry, approval.origin(), true) else {
        stale(vault, effects, approval, Some(session), Some(&login_id));
        return unavailable(request, "staleRequest");
    };
    if !credential_fields_valid(&entry) {
        stale(vault, effects, approval, Some(session), Some(&login_id));
        return unavailable(request, "staleRequest");
    }
    let now = unix_timestamp();
    let Ok(mut changes) = read_pending(session) else {
        return unavailable(request, "approvalUnavailable");
    };
    prune(&mut changes, now);
    if !has_room(&changes) {
        return unavailable(request, "approvalUnavailable");
    }
    let (Ok(new_password), Ok((handle, digest))) = (generate_password(style), issue_handle())
    else {
        return unavailable(request, "approvalUnavailable");
    };
    let current_password = Zeroizing::new(entry.password.clone());
    let Ok(next) = payload_with_saved_login(&payload, entry, Some(new_password.to_string()), now)
    else {
        return unavailable(request, "approvalUnavailable");
    };
    let history_id = next
        .history
        .iter()
        .rev()
        .find(|item| item.item.id() == login_id)
        .map(|item| item.id.clone());
    let revision = next
        .entries
        .iter()
        .find(|item| item.id == login_id)
        .map_or(0, |item| item.revision);
    drop(payload);
    let prepared = PendingChange {
        id: random_id(),
        handle_digest: digest,
        item_id: login_id.clone(),
        history_id,
        origin: approval.origin().canonical(),
        host: approval.origin().hostname.clone(),
        kind: PendingKind::Change,
        revision,
        created_at: now,
        fill: FillState::Unknown,
        accepted_at: None,
        resolution: Resolution::Unconfirmed,
        resolved_at: None,
        username_attached: false,
        applied: false,
    };
    if record_unapplied(session, &mut changes, prepared).is_err() {
        return unavailable(request, "approvalUnavailable");
    }
    if commit_payload_change(session, next).is_err() {
        abandon_unapplied(session, &mut changes);
        return unavailable(request, "approvalUnavailable");
    }
    mark_applied(session, &mut changes);
    vault.advance_session_epoch();
    note(
        vault,
        Some(session),
        approval
            .draft(Outcome::Updated)
            .item(&login_id, "login")
            .field("password")
            .match_kind(MatchKind::parse(match_kind.as_str())),
    );
    BrowserResponse::changed(
        request,
        current_password.to_string(),
        new_password.to_string(),
        handle.to_string(),
        match_kind.as_str(),
    )
}

pub fn create_response_in_state(
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
) -> BrowserReply {
    effects.record_browser_host_registration("create_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return unavailable(request, "staleRequest").into();
    };
    if style_of(request).is_none() {
        return unavailable(request, "staleRequest").into();
    }
    let epoch = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => return unavailable(request, "approvalUnavailable").into(),
        };
        let Some(session) = session.as_ref() else {
            effects.record_browser_host_registration("create_locked");
            vault.release_record.append_locked(browser_draft(
                ApprovalKind::Create,
                Outcome::Locked,
                &origin.hostname,
            ));
            return unavailable(request, "locked").into();
        };
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => return unavailable(request, "approvalUnavailable").into(),
        };
        if never_saves(&payload.never_save_sites, &origin) {
            effects.record_browser_host_registration("create_never_site");
            record_in(
                vault,
                Some(session),
                browser_draft(ApprovalKind::Create, Outcome::NeverSave, &origin.hostname),
            );
            return unavailable(request, "approvalDeclined").into();
        }
        vault.session_epoch()
    };
    let hostname = origin.hostname.clone();
    let canonical = origin.canonical();
    match register_approval(
        fill_state,
        &request.request_id,
        origin.clone(),
        epoch,
        ApprovalKind::Create,
        ApprovalRequest::Create,
        |approval_id| {
            ApprovalEvent::Create(BrowserCreateRequestEvent {
                approval_id: approval_id.to_string(),
                origin: canonical,
                hostname,
                expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
                expires_at_unix_ms: approval_expires_at_unix_ms(),
            })
        },
    ) {
        Ok(offer) => offer.into(),
        Err(RegisterError::Begin(reason)) => {
            refused(vault, ApprovalKind::Create, &origin, begin_refusal(reason));
            unavailable(request, reason).into()
        }
        Err(RegisterError::Publish) => unavailable(request, "approvalUnavailable").into(),
    }
}

fn new_login(origin: &NormalizedOrigin, password: String) -> LoginInput {
    LoginInput {
        urls: Vec::new(),
        tags: Vec::new(),
        id: None,
        title: bounded_display(&origin.hostname, 160),
        url: origin.canonical(),
        username: String::new(),
        email: String::new(),
        password,
        folder: String::new(),
        folder_id: None,
        totp: None,
        backup_codes: Vec::new(),
        keep_backup_codes: false,
        recovery_email: String::new(),
        recovery_phone: String::new(),
        recovery_not_applicable: false,
        notes: String::new(),
        match_rule: None,
        custom_fields: None,
        kept_secrets: None,
    }
}

pub fn complete_create_in_state(
    vault: &VaultState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
    approval: &BrowserApproval,
    decision: ApprovalDecision,
    peer_connected: &dyn Fn() -> bool,
) -> BrowserResponse {
    match decision {
        ApprovalDecision::Approved => {}
        ApprovalDecision::Denied => return unavailable(request, "approvalDeclined"),
        _ => return unavailable(request, "invalidSelection"),
    }
    if !peer_connected() {
        record(vault, approval.draft(Outcome::ConnectionClosed));
        effects.emit_browser_approval_cancelled(
            ApprovalKind::Create,
            approval.approval_id(),
            "connectionClosed",
        );
        return unavailable(request, "staleRequest");
    }
    let Some(style) = style_of(request) else {
        return unavailable(request, "staleRequest");
    };
    let mut guard = match vault.session.lock() {
        Ok(guard) => guard,
        Err(_) => return unavailable(request, "approvalUnavailable"),
    };
    if vault.session_epoch() != approval.epoch() {
        stale(vault, effects, approval, guard.as_ref(), None);
        return unavailable(request, "staleRequest");
    }
    let Some(session) = guard.as_mut() else {
        stale(vault, effects, approval, None, None);
        return unavailable(request, "locked");
    };
    let Ok(payload) = session.open_payload() else {
        return unavailable(request, "approvalUnavailable");
    };
    if never_saves(&payload.never_save_sites, approval.origin()) {
        note(vault, Some(session), approval.draft(Outcome::NeverSave));
        return unavailable(request, "approvalDeclined");
    }
    let now = unix_timestamp();
    let Ok(mut changes) = read_pending(session) else {
        return unavailable(request, "approvalUnavailable");
    };
    prune(&mut changes, now);
    if !has_room(&changes) {
        return unavailable(request, "approvalUnavailable");
    }
    let (Ok(password), Ok((handle, digest))) = (generate_password(style), issue_handle()) else {
        return unavailable(request, "approvalUnavailable");
    };
    let Ok(entry) = entry_from_input(new_login(approval.origin(), password.to_string())) else {
        return unavailable(request, "approvalUnavailable");
    };
    let item_id = entry.id.clone();
    let revision = entry.revision;
    let mut next: VaultPayload = payload.clone();
    drop(payload);
    next.entries.push(entry);
    let prepared = PendingChange {
        id: random_id(),
        handle_digest: digest,
        item_id: item_id.clone(),
        history_id: None,
        origin: approval.origin().canonical(),
        host: approval.origin().hostname.clone(),
        kind: PendingKind::New,
        revision,
        created_at: now,
        fill: FillState::Unknown,
        accepted_at: None,
        resolution: Resolution::Unconfirmed,
        resolved_at: None,
        username_attached: false,
        applied: false,
    };
    if record_unapplied(session, &mut changes, prepared).is_err() {
        return unavailable(request, "approvalUnavailable");
    }
    if commit_payload_change(session, next).is_err() {
        abandon_unapplied(session, &mut changes);
        return unavailable(request, "approvalUnavailable");
    }
    mark_applied(session, &mut changes);
    vault.advance_session_epoch();
    note(
        vault,
        Some(session),
        approval
            .draft(Outcome::Saved)
            .item(&item_id, "login")
            .field("password"),
    );
    BrowserResponse::created(request, password.to_string(), handle.to_string())
}

fn record_unapplied(
    session: &UnlockedVault,
    changes: &mut Vec<PendingChange>,
    prepared: PendingChange,
) -> VaultResult<()> {
    changes.push(prepared);
    write_pending(session, changes).inspect_err(|_| {
        changes.pop();
    })
}

fn abandon_unapplied(session: &UnlockedVault, changes: &mut Vec<PendingChange>) {
    changes.pop();
    let _ = write_pending(session, changes);
}

fn mark_applied(session: &UnlockedVault, changes: &mut [PendingChange]) {
    if let Some(prepared) = changes.last_mut() {
        prepared.applied = true;
    }
    let _ = write_pending(session, changes);
}

fn wire_state(change: &PendingChange) -> &'static str {
    match change.resolution {
        Resolution::Unconfirmed if change.accepted_at.is_some() => "confirmed",
        Resolution::Unconfirmed => "unconfirmed",
        Resolution::Kept => "confirmed",
        Resolution::Returned | Resolution::Discarded => "returned",
    }
}

fn attach_username(
    session: &mut UnlockedVault,
    change: &mut PendingChange,
    username: &str,
    now: u64,
) -> VaultResult<bool> {
    let username = bounded_display(username.trim(), MAX_USERNAME_CHARS);
    if username.chars().any(is_control_or_format) {
        return Ok(false);
    }
    if username.is_empty()
        || change.kind != PendingKind::New
        || !change.is_unresolved()
        || change.username_attached
    {
        return Ok(false);
    }
    let payload = session.open_payload()?;
    let Some(entry) = payload
        .entries
        .iter()
        .find(|entry| entry.id == change.item_id)
    else {
        return Ok(false);
    };
    if !entry.username.is_empty() || entry.revision != change.revision {
        return Ok(false);
    }
    let mut updated = entry.clone();
    updated.username = username;
    let next = payload_with_saved_login(&payload, updated, None, now)?;
    let revision = next
        .entries
        .iter()
        .find(|entry| entry.id == change.item_id)
        .map_or(change.revision, |entry| entry.revision);
    drop(payload);
    commit_payload_change(session, next)?;
    change.username_attached = true;
    change.revision = revision;
    Ok(true)
}

fn is_control_or_format(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0001}'
                | '\u{E0020}'..='\u{E007F}'
        )
}

pub fn pending_response_in_state(vault: &VaultState, request: &BrowserRequest) -> BrowserResponse {
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return unavailable(request, "staleRequest");
    };
    let (Some(handle), Some(action)) = (request.handle.as_deref(), request.action.as_deref())
    else {
        return unavailable(request, "staleRequest");
    };
    let mut guard = match vault.session.lock() {
        Ok(guard) => guard,
        Err(_) => return unavailable(request, "approvalUnavailable"),
    };
    let Some(session) = guard.as_mut() else {
        return unavailable(request, "locked");
    };
    let now = unix_timestamp();
    let Ok(mut changes) = read_pending(session) else {
        return unavailable(request, "approvalUnavailable");
    };
    prune(&mut changes, now);
    let canonical = origin.canonical();
    let Some(index) = find_by_handle(&mut changes, handle, &canonical, now)
        .map(|found| found.id.clone())
        .and_then(|id| changes.iter().position(|change| change.id == id))
    else {
        return BrowserResponse::pending_state(request, "unknown");
    };
    let mut attached = false;
    {
        let change = &mut changes[index];
        match action {
            "filled" if change.fill == FillState::Unknown => change.fill = FillState::Filled,
            "notFilled" if change.fill == FillState::Unknown => change.fill = FillState::NotFilled,
            "accepted" if change.is_unresolved() && change.accepted_at.is_none() => {
                change.accepted_at = Some(now);
                if change.kind == PendingKind::Change {
                    change.resolution = Resolution::Kept;
                    change.resolved_at = Some(now);
                }
                if let Some(username) = request.username.as_deref() {
                    attached = attach_username(session, change, username, now).unwrap_or(false);
                }
            }
            _ => {}
        }
    }
    if attached {
        vault.advance_session_epoch();
    }
    let state = wire_state(&changes[index]);
    if write_pending(session, &changes).is_err() {
        return unavailable(request, "approvalUnavailable");
    }
    BrowserResponse::pending_state(request, state)
}

fn history_password(payload: &VaultPayload, history_id: &str) -> Option<Zeroizing<String>> {
    payload
        .history
        .iter()
        .find(|entry| entry.id == history_id)
        .and_then(|entry| match &entry.item {
            TaggedItem::Login(login) => Some(Zeroizing::new(login.password.clone())),
            _ => None,
        })
}

fn newer_password_saved(payload: &VaultPayload, change: &PendingChange, live: &str) -> bool {
    let Some(history_id) = change.history_id.as_deref() else {
        return false;
    };
    let mut versions = payload
        .history
        .iter()
        .filter_map(|entry| match &entry.item {
            TaggedItem::Login(login) if login.id == change.item_id => {
                Some((entry.id.as_str(), login))
            }
            _ => None,
        });
    if !versions.any(|(id, _)| id == history_id) {
        return false;
    }
    versions
        .next()
        .is_some_and(|(_, after_change)| after_change.password != live)
}

fn views(session: &UnlockedVault, changes: &[PendingChange], now: u64) -> Vec<PendingChangeView> {
    let Ok(payload) = session.open_payload() else {
        return Vec::new();
    };
    let mut views: Vec<PendingChangeView> = changes
        .iter()
        .filter(|change| change.is_unresolved())
        .filter_map(|change| {
            let entry = payload
                .entries
                .iter()
                .find(|entry| entry.id == change.item_id)?;
            let in_history = change.history_id.as_deref().is_some_and(|history_id| {
                payload.history.iter().any(|item| {
                    item.id == history_id
                        && item.captured_at > now.saturating_sub(HISTORY_RETENTION_SECONDS)
                })
            });
            let age = now.saturating_sub(change.created_at);
            let current = entry.revision == change.revision;
            let superseded = change.kind == PendingKind::Change
                && !current
                && newer_password_saved(&payload, change, &entry.password);
            let days_left = (change.kind == PendingKind::Change && in_history).then(|| {
                let left = HISTORY_RETENTION_SECONDS.saturating_sub(age);
                u32::try_from(left.div_ceil(DAY_SECS)).unwrap_or(u32::MAX)
            });
            Some(PendingChangeView {
                id: change.id.clone(),
                item_id: change.item_id.clone(),
                kind: change.kind,
                host: change.host.clone(),
                title: entry.title.clone(),
                username: entry.username.clone(),
                created_at: change.created_at,
                fill: change.fill,
                accepted: change.accepted_at.is_some(),
                can_go_back: change.kind == PendingKind::Change && in_history && current,
                superseded,
                days_left,
                urgent: change.kind == PendingKind::Change
                    && in_history
                    && age >= ESCALATE_AFTER_SECS,
            })
        })
        .collect();
    views.reverse();
    views.sort_by_key(|view| std::cmp::Reverse(view.created_at));
    views
}

pub fn list_pending_changes_in_state(vault: &VaultState) -> VaultResult<PendingChangeList> {
    let session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let Some(session) = session.as_ref() else {
        return Ok(PendingChangeList {
            changes: Vec::new(),
            snapshot: None,
        });
    };
    let now = unix_timestamp();
    let changes = read_pending(session)?;
    Ok(PendingChangeList {
        changes: views(session, &changes, now),
        snapshot: Some(session.snapshot()),
    })
}

fn resolve_with(
    vault: &VaultState,
    id: &str,
    action: impl FnOnce(&mut UnlockedVault, &mut Vec<PendingChange>, usize, u64) -> VaultResult<bool>,
) -> VaultResult<PendingChangeList> {
    let mut guard = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = guard.as_mut().ok_or(UNLOCK_FIRST)?;
    let now = unix_timestamp();
    let mut changes = read_pending(session)?;
    prune(&mut changes, now);
    let index = changes
        .iter()
        .position(|change| change.id == id && change.is_unresolved())
        .ok_or(NO_LONGER_WAITING)?;
    let wrote_vault = action(session, &mut changes, index, now)?;
    if wrote_vault {
        vault.advance_session_epoch();
    }
    write_pending(session, &changes)?;
    Ok(PendingChangeList {
        changes: views(session, &changes, now),
        snapshot: Some(session.snapshot()),
    })
}

pub fn keep_pending_change_in_state(
    vault: &VaultState,
    id: &str,
) -> VaultResult<PendingChangeList> {
    resolve_with(vault, id, |_, changes, index, now| {
        changes[index].resolution = Resolution::Kept;
        changes[index].resolved_at = Some(now);
        Ok(false)
    })
}

pub fn go_back_pending_change_in_state(
    vault: &VaultState,
    id: &str,
) -> VaultResult<PendingChangeList> {
    resolve_with(vault, id, |session, changes, index, now| {
        let change = changes[index].clone();
        if change.kind != PendingKind::Change {
            return Err(NO_LONGER_WAITING.into());
        }
        let payload = session.open_payload()?;
        let entry = payload
            .entries
            .iter()
            .find(|entry| entry.id == change.item_id)
            .cloned()
            .ok_or("That login no longer exists.")?;
        if entry.revision != change.revision {
            return Err("This login changed after that. Pick a version in its history.".into());
        }
        let old_password = change
            .history_id
            .as_deref()
            .and_then(|history_id| history_password(&payload, history_id))
            .ok_or("The old password is no longer in history.")?;
        let next = payload_with_saved_login(&payload, entry, Some(old_password.to_string()), now)?;
        drop(payload);
        commit_payload_change(session, next)?;
        changes[index].resolution = Resolution::Returned;
        changes[index].resolved_at = Some(now);
        Ok(true)
    })
}

pub fn discard_pending_login_in_state(
    vault: &VaultState,
    id: &str,
) -> VaultResult<PendingChangeList> {
    resolve_with(vault, id, |session, changes, index, now| {
        let change = changes[index].clone();
        if change.kind != PendingKind::New {
            return Err(NO_LONGER_WAITING.into());
        }
        let payload = session.open_payload()?;
        let mut next: VaultPayload = payload.clone();
        drop(payload);
        let item = next
            .take_active_item(&change.item_id)
            .ok_or("That login no longer exists.")?;
        if !matches!(item, TaggedItem::Login(_)) {
            return Err("That login no longer exists.".into());
        }
        trash_item(&mut next, item);
        commit_payload_change(session, next)?;
        changes[index].resolution = Resolution::Discarded;
        changes[index].resolved_at = Some(now);
        Ok(true)
    })
}
