use std::{
    sync::mpsc::RecvTimeoutError,
    time::{Duration, Instant},
};

use sesame_core::secret_fields::redact;
use zeroize::{Zeroize, Zeroizing};

use super::cli_broker::{
    ApprovalSubject, CliApprovalRequestEvent, CliApprovalState, CliCandidate, CliCommandKind,
    CliDecision, CliUnlockRequestEvent, StartRefusal, CLI_UNLOCK_TIMEOUT, COOLING_MESSAGE,
};
use super::logins::terminal_totp_in_session;
use super::reveal::{
    record_terminal_release_in, terminal_copy_item_field_in_state, terminal_item_field_in_state,
    TerminalField, VAULT_CHANGED,
};
use super::terminal_allowances::{allowed_request, TerminalAllowances, TerminalOrigin};
use super::DesktopEffects;
use crate::cli_protocol::{
    bounded_title_text, parse_request, CliCommand, CliErrorCode, CliField, CliItemSummary,
    CliReply, WaitReason, MAX_CLI_LIST_BYTES, MAX_CLI_REPLY_BYTES, MAX_FIELD_CHARS,
    MAX_TOTP_REMAINING_SECONDS, MAX_WAITING_FRAMES,
};
use crate::release::{ReleasePresence, PRESENCE_REQUIRED};
use crate::vault::release_record::EntryKind;
use crate::vault::{TaggedItem, VaultState};

pub const CLI_POLL: Duration = Duration::from_millis(200);
const FRAME_MARGIN_BYTES: usize = 512;
const PRESENCE_MESSAGE: &str =
    "Sesame needs your master password before it releases this value. Try again and enter it in Sesame.";
const EMPTY_FIELD_ERROR: &str = "Nothing is saved in that field for this item.";
const PREEMPTED_MESSAGE: &str =
    "Sesame set this request aside to answer your browser. Try again shortly.";
const ITEM_TOO_LARGE: &str =
    "This item is too large to send at once. Ask for one field at a time instead.";
const LIST_TOO_LARGE: &str =
    "The list of items is too large to send to a terminal. Browse it in the Sesame window instead.";
const LIST_BUDGET_BYTES: usize = MAX_CLI_LIST_BYTES - MAX_WAITING_FRAMES * MAX_CLI_REPLY_BYTES;

pub trait CliHost {
    fn peer_connected(&self) -> bool;
    fn send(&self, reply: &CliReply) -> bool;
    fn unlock_requested(&self, event: &CliUnlockRequestEvent);
    fn unlock_ended(&self, reason: &'static str);
    fn approval_requested(&self, event: &CliApprovalRequestEvent);
    fn approval_cancelled(&self, approval_id: &str, reason: &'static str);
    fn allowances_changed(&self);
}

pub struct CliContext<'a> {
    pub vault: &'a VaultState,
    pub presence: &'a ReleasePresence,
    pub effects: &'a dyn DesktopEffects,
    pub approvals: &'a CliApprovalState,
    pub allowances: &'a TerminalAllowances,
    pub host: &'a dyn CliHost,
    pub poll: Duration,
    pub unlock_timeout: Duration,
    pub list_budget: usize,
}

impl<'a> CliContext<'a> {
    pub fn new(
        vault: &'a VaultState,
        presence: &'a ReleasePresence,
        effects: &'a dyn DesktopEffects,
        approvals: &'a CliApprovalState,
        allowances: &'a TerminalAllowances,
        host: &'a dyn CliHost,
    ) -> Self {
        Self {
            vault,
            presence,
            effects,
            approvals,
            allowances,
            host,
            poll: CLI_POLL,
            unlock_timeout: CLI_UNLOCK_TIMEOUT,
            list_budget: LIST_BUDGET_BYTES,
        }
    }
}

enum Stop {
    Reply(CliErrorCode),
    ReplyWith(CliErrorCode, &'static str),
    Gone,
}

pub fn parse_or_refuse(payload: &[u8]) -> Result<(String, CliCommand), Box<CliReply>> {
    parse_request(payload).map_err(|rejection| {
        Box::new(CliReply::error(
            rejection.request_id.as_deref(),
            rejection.code,
        ))
    })
}

pub fn serve_cli_request(context: &CliContext<'_>, payload: &[u8], origin: &TerminalOrigin) {
    let (request_id, command) = match parse_or_refuse(payload) {
        Ok(parsed) => parsed,
        Err(refusal) => {
            context.host.send(&refusal);
            return;
        }
    };
    let flight = match context.approvals.start(&request_id) {
        Ok(flight) => flight,
        Err(StartRefusal::Code(code)) => {
            context.host.send(&CliReply::error(Some(&request_id), code));
            return;
        }
        Err(StartRefusal::CoolingOff) => {
            context.host.send(&CliReply::error_with(
                Some(&request_id),
                CliErrorCode::Busy,
                COOLING_MESSAGE,
            ));
            return;
        }
    };
    let frames = match answer(context, &request_id, &command, origin) {
        Ok(frames) => frames,
        Err(Stop::Reply(code)) => vec![CliReply::error(Some(&request_id), code)],
        Err(Stop::ReplyWith(code, message)) => {
            vec![CliReply::error_with(Some(&request_id), code, message)]
        }
        Err(Stop::Gone) => Vec::new(),
    };
    for frame in &frames {
        if !context.host.send(frame) {
            break;
        }
    }
    drop(flight);
}

fn command_kind(command: &CliCommand) -> CliCommandKind {
    match command {
        CliCommand::List => CliCommandKind::List,
        CliCommand::Get { .. } => CliCommandKind::Get,
        CliCommand::Totp { .. } => CliCommandKind::Totp,
    }
}

fn command_name(command: &CliCommand) -> &'static str {
    match command {
        CliCommand::List => "list",
        CliCommand::Get { .. } => "get",
        CliCommand::Totp { .. } => "totp",
    }
}

fn requested_field(command: &CliCommand) -> Option<&str> {
    match command {
        CliCommand::Get { field, .. } => field.as_deref(),
        CliCommand::Totp { .. } => Some("totp"),
        CliCommand::List => None,
    }
}

fn unlocked_epoch(vault: &VaultState) -> Option<u64> {
    let session = vault.session.lock().ok()?;
    session.as_ref()?;
    Some(vault.session_epoch())
}

struct Unlocked {
    epoch: u64,
    after_wait: Option<Instant>,
}

fn wait_for_unlock(
    context: &CliContext<'_>,
    request_id: &str,
    command: &CliCommand,
    origin: &TerminalOrigin,
) -> Result<Unlocked, Stop> {
    if let Some(epoch) = unlocked_epoch(context.vault) {
        return Ok(Unlocked {
            epoch,
            after_wait: None,
        });
    }
    if !context
        .host
        .send(&CliReply::waiting(request_id, WaitReason::Unlock))
    {
        return Err(Stop::Gone);
    }
    context.host.unlock_requested(&CliUnlockRequestEvent {
        command: command_kind(command),
        terminal: origin.device.clone(),
        program: origin.program.clone(),
        remote: origin.remote,
    });
    let deadline = Instant::now() + context.unlock_timeout;
    loop {
        std::thread::sleep(
            context
                .poll
                .min(deadline.saturating_duration_since(Instant::now())),
        );
        let observed = Instant::now();
        if observed < deadline {
            if let Some(epoch) = unlocked_epoch(context.vault).filter(|_| Instant::now() < deadline)
            {
                context.host.unlock_ended("unlocked");
                return Ok(Unlocked {
                    epoch,
                    after_wait: Some(observed),
                });
            }
        }
        if !context.host.peer_connected() {
            context.host.unlock_ended("connectionClosed");
            context.approvals.note_unanswered();
            return Err(Stop::Gone);
        }
        if Instant::now() >= deadline {
            context.host.unlock_ended("expired");
            context.approvals.note_unanswered();
            return Err(Stop::Reply(CliErrorCode::Timeout));
        }
    }
}

struct Subject {
    candidates: Vec<CliCandidate>,
    field_hidden: bool,
}

fn with_session<T>(
    vault: &VaultState,
    epoch: u64,
    read: impl FnOnce(&crate::vault::UnlockedVault) -> Result<T, Stop>,
) -> Result<T, Stop> {
    let session = vault
        .session
        .lock()
        .map_err(|_| Stop::Reply(CliErrorCode::Unavailable))?;
    let session = session.as_ref().ok_or(Stop::Reply(CliErrorCode::Stale))?;
    if vault.session_epoch() != epoch {
        return Err(Stop::Reply(CliErrorCode::Stale));
    }
    read(session)
}

fn all_items(session: &crate::vault::UnlockedVault) -> Vec<CliCandidate> {
    let snapshot = session.snapshot();
    let mut items: Vec<CliCandidate> = snapshot
        .entries
        .iter()
        .map(|entry| CliCandidate {
            id: entry.id.clone(),
            kind: "login".to_string(),
            title: entry.title.clone(),
            ..CliCandidate::default()
        })
        .chain(snapshot.items.iter().map(|item| CliCandidate {
            id: item.id.clone(),
            kind: item.kind.to_string(),
            title: item.title.clone(),
            ..CliCandidate::default()
        }))
        .collect();
    items.sort_by(|left, right| {
        left.title
            .to_lowercase()
            .cmp(&right.title.to_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });
    items
}

fn matching_items(session: &crate::vault::UnlockedVault, wanted: &str) -> Vec<CliCandidate> {
    let items = all_items(session);
    let wanted = wanted.trim();
    if let Some(exact) = items.iter().find(|item| item.id == wanted) {
        return vec![exact.clone()];
    }
    let wanted = wanted.to_lowercase();
    items
        .into_iter()
        .filter(|item| item.title.trim().to_lowercase() == wanted)
        .collect()
}

fn resolve_subject(vault: &VaultState, epoch: u64, command: &CliCommand) -> Result<Subject, Stop> {
    let (item, field) = match command {
        CliCommand::List => {
            return Ok(Subject {
                candidates: Vec::new(),
                field_hidden: false,
            })
        }
        CliCommand::Get { item, field, .. } => (item, field.as_deref()),
        CliCommand::Totp { item, .. } => (item, None),
    };
    with_session(vault, epoch, |session| {
        let mut candidates = matching_items(session, item);
        let mut field_hidden = false;
        if let Some(field) = field {
            for candidate in &mut candidates {
                let opened = session
                    .open_item(&candidate.id)
                    .map_err(|_| Stop::Reply(CliErrorCode::Unavailable))?;
                let fields = described_fields(&opened);
                if let Some(described) = find_field(&fields, field) {
                    candidate.field_name = Some(display_name(described));
                    candidate.field_hidden = described.hidden;
                    field_hidden |= described.hidden;
                }
            }
        }
        Ok(Subject {
            candidates: candidates
                .into_iter()
                .map(|candidate| CliCandidate {
                    title: bounded_title_text(&candidate.title),
                    ..candidate
                })
                .collect(),
            field_hidden,
        })
    })
}

fn answer(
    context: &CliContext<'_>,
    request_id: &str,
    command: &CliCommand,
    origin: &TerminalOrigin,
) -> Result<Vec<CliReply>, Stop> {
    let unlocked = wait_for_unlock(context, request_id, command, origin)?;
    let epoch = unlocked.epoch;
    let fresh_password_since = unlocked.after_wait;
    let subject = resolve_subject(context.vault, epoch, command)?;
    let allowed_revision = context.allowances.covering_revision(origin, epoch);
    let allowed = allowed_revision.is_some();
    let needs_presence = subject.field_hidden
        && (fresh_password_since.is_some() || context.presence.require(epoch).is_err());
    let not_found = !matches!(command, CliCommand::List) && subject.candidates.is_empty();
    if not_found && allowed {
        return Err(Stop::Reply(CliErrorCode::NotFound));
    }
    let prompt_needed = !allowed || subject.candidates.len() > 1 || needs_presence || not_found;
    let event = CliApprovalRequestEvent {
        approval_id: String::new(),
        command: command_kind(command),
        field: match command {
            CliCommand::Get { field, .. } => field.clone(),
            _ => None,
        },
        field_hidden: subject.field_hidden,
        copy: command.copies(),
        candidates: subject.candidates.clone(),
        not_found: match command {
            CliCommand::Get { item, .. } | CliCommand::Totp { item, .. } if not_found => {
                Some(item.clone())
            }
            _ => None,
        },
        terminal: origin.device.clone(),
        program: origin.program.clone(),
        remote: origin.remote,
        can_allow_terminal: origin.key.is_some() && !allowed && !not_found,
        needs_presence,
        allowed,
        expires_in_ms: 0,
    };
    let chosen = if prompt_needed {
        let decision = prompt(context, request_id, epoch, event, &subject, not_found)?;
        match decision {
            CliDecision::Allow { .. } => context.approvals.note_approved(),
            CliDecision::Dismiss => context.approvals.note_missing_dismissed(),
            CliDecision::Withdrawn => {}
            _ => context.approvals.note_unanswered(),
        }
        match decision {
            CliDecision::Allow {
                item_id,
                terminal_grant,
            } => {
                ensure_epoch(context.vault, epoch)?;
                if terminal_grant
                    .is_some_and(|revision| context.allowances.grant(origin, epoch, revision))
                {
                    context.host.allowances_changed();
                }
                match item_id {
                    Some(id) => Some(
                        subject
                            .candidates
                            .iter()
                            .find(|candidate| candidate.id == id)
                            .cloned()
                            .ok_or(Stop::Reply(CliErrorCode::Cancelled))?,
                    ),
                    None => None,
                }
            }
            CliDecision::Dismiss => return Err(Stop::Reply(CliErrorCode::NotFound)),
            CliDecision::Deny | CliDecision::InvalidSelection => {
                return Err(Stop::Reply(CliErrorCode::Cancelled))
            }
            CliDecision::Withdrawn => return Err(Stop::Reply(CliErrorCode::Stale)),
            CliDecision::Preempted => {
                return Err(Stop::ReplyWith(CliErrorCode::Busy, PREEMPTED_MESSAGE))
            }
        }
    } else {
        subject.candidates.first().cloned()
    };
    if not_found {
        return Err(Stop::Reply(CliErrorCode::NotFound));
    }
    ensure_epoch(context.vault, epoch)?;
    let frames = release(
        context,
        request_id,
        command,
        chosen.as_ref(),
        Freshness {
            epoch,
            password_since: fresh_password_since,
        },
    )?;
    if let Some(revision) = allowed_revision.filter(|_| !prompt_needed) {
        context.allowances.note_request(
            origin,
            revision,
            allowed_request(
                command_name(command),
                chosen
                    .as_ref()
                    .map(|candidate| (candidate.id.as_str(), candidate.kind.as_str())),
                requested_field(command),
            ),
        );
        context.host.allowances_changed();
    }
    Ok(frames)
}

fn ensure_epoch(vault: &VaultState, epoch: u64) -> Result<(), Stop> {
    if unlocked_epoch(vault) == Some(epoch) {
        Ok(())
    } else {
        Err(Stop::Reply(CliErrorCode::Stale))
    }
}

fn prompt(
    context: &CliContext<'_>,
    request_id: &str,
    epoch: u64,
    event: CliApprovalRequestEvent,
    subject: &Subject,
    not_found: bool,
) -> Result<CliDecision, Stop> {
    let terminal_allowed = event.can_allow_terminal;
    let offer = context
        .approvals
        .begin(ApprovalSubject {
            request_id: request_id.to_string(),
            epoch,
            offered: subject
                .candidates
                .iter()
                .map(|candidate| candidate.id.clone())
                .collect(),
            not_found,
            terminal_allowed,
            event,
        })
        .map_err(Stop::Reply)?;
    let approval_id = offer.approval_id.clone();
    if !context
        .host
        .send(&CliReply::waiting(request_id, WaitReason::Approval))
    {
        context.approvals.revoke(&approval_id);
        return Err(Stop::Gone);
    }
    context.host.approval_requested(&offer.event);
    let stop = |reason: &'static str, result: Stop| {
        context.approvals.revoke(&approval_id);
        context.host.approval_cancelled(&approval_id, reason);
        Err(result)
    };
    let unanswered = |reason: &'static str, result: Stop| {
        context.approvals.note_unanswered();
        stop(reason, result)
    };
    let preempted = || {
        unanswered(
            "preempted",
            Stop::ReplyWith(CliErrorCode::Busy, PREEMPTED_MESSAGE),
        )
    };
    loop {
        let remaining = offer.deadline.saturating_duration_since(Instant::now());
        match offer
            .receiver
            .recv_timeout(context.poll.min(remaining).max(Duration::from_millis(1)))
        {
            Ok(CliDecision::Withdrawn) | Err(RecvTimeoutError::Disconnected) => {
                return stop("vaultChanged", Stop::Reply(CliErrorCode::Stale));
            }
            Ok(CliDecision::Preempted) => return preempted(),
            Ok(_) if context.vault.session_epoch() != epoch => {
                return stop("vaultChanged", Stop::Reply(CliErrorCode::Stale));
            }
            Ok(_) if !context.host.peer_connected() => {
                return unanswered("connectionClosed", Stop::Gone);
            }
            Ok(decision) => return Ok(decision),
            Err(RecvTimeoutError::Timeout) => {}
        }
        if !context.host.peer_connected() {
            return unanswered("connectionClosed", Stop::Gone);
        }
        if Instant::now() >= offer.deadline {
            return unanswered("expired", Stop::Reply(CliErrorCode::Timeout));
        }
        if context.vault.session_epoch() != epoch
            || !context.approvals.is_bound(&approval_id, request_id, epoch)
        {
            match offer.receiver.try_recv() {
                Ok(CliDecision::Preempted) => return preempted(),
                Ok(decision)
                    if context.vault.session_epoch() == epoch
                        && decision != CliDecision::Withdrawn =>
                {
                    if !context.host.peer_connected() {
                        return unanswered("connectionClosed", Stop::Gone);
                    }
                    return Ok(decision);
                }
                _ => {}
            }
            return stop("vaultChanged", Stop::Reply(CliErrorCode::Stale));
        }
    }
}

struct DescribedField {
    name: String,
    key: String,
    hidden: bool,
    present: bool,
    value: Option<Zeroizing<String>>,
    altered: bool,
}

fn visible(name: &str, value: &str) -> DescribedField {
    DescribedField {
        name: name.to_string(),
        key: name.to_string(),
        hidden: false,
        present: !value.trim().is_empty(),
        value: Some(Zeroizing::new(value.to_string())),
        altered: false,
    }
}

fn hidden(name: &str, key: &str, present: bool) -> DescribedField {
    DescribedField {
        name: name.to_string(),
        key: key.to_string(),
        hidden: true,
        present,
        value: None,
        altered: false,
    }
}

fn control_picture(character: char) -> char {
    match u32::from(character) {
        code @ 0x00..=0x1f => char::from_u32(0x2400 + code).unwrap_or('\u{fffd}'),
        0x7f => '\u{2421}',
        _ if character.is_control() => '\u{fffd}',
        _ => character,
    }
}

fn labelled(label: &str, key: &str) -> (String, bool) {
    let trimmed =
        label.trim_matches(|character: char| character.is_whitespace() && !character.is_control());
    if trimmed.is_empty() {
        return (key.to_string(), false);
    }
    let shown: String = trimmed
        .chars()
        .map(control_picture)
        .take(MAX_FIELD_CHARS)
        .collect();
    let altered = shown != trimmed;
    (shown, altered)
}

fn labelled_field(field: DescribedField, label: &str) -> DescribedField {
    let (name, altered) = labelled(label, &field.key);
    DescribedField {
        name,
        altered,
        ..field
    }
}

fn name_clashes(fields: &[DescribedField], index: usize) -> bool {
    let name = fields[index].name.to_lowercase();
    fields
        .iter()
        .enumerate()
        .any(|(other, field)| other != index && field.name.to_lowercase() == name)
}

fn unconfusable(mut fields: Vec<DescribedField>) -> Vec<DescribedField> {
    let clashing: Vec<usize> = (0..fields.len())
        .filter(|index| fields[*index].altered && name_clashes(&fields, *index))
        .collect();
    for index in clashing {
        fields[index].name = fields[index].key.clone();
    }
    let unreachable: Vec<usize> = (0..fields.len())
        .filter(|index| {
            fields[*index].name != fields[*index].key
                && find_index(&fields, &fields[*index].name) != Some(*index)
        })
        .collect();
    for index in unreachable {
        fields[index].name = fields[index].key.clone();
    }
    fields
}

fn described_fields(item: &TaggedItem) -> Vec<DescribedField> {
    let mut redacted = item.clone();
    let present = redact(&mut redacted);
    let is_present = |key: &str| present.iter().any(|slot| slot == key);
    let mut fields = Vec::new();
    let mut custom = Vec::new();
    let mut legacy = Vec::new();
    match &mut redacted {
        TaggedItem::Login(entry) => {
            entry.totp.zeroize();
            let backup_codes = !entry.backup_codes.is_empty();
            entry.backup_codes.zeroize();
            fields.push(visible("username", &entry.username));
            fields.push(visible("email", &entry.email));
            fields.push(visible("url", &entry.url));
            fields.push(visible("notes", entry.notes.as_deref().unwrap_or_default()));
            fields.push(visible(
                "recoveryEmail",
                entry.recovery_email.as_deref().unwrap_or_default(),
            ));
            fields.push(visible(
                "recoveryPhone",
                entry.recovery_phone.as_deref().unwrap_or_default(),
            ));
            fields.push(hidden("password", "password", is_present("password")));
            fields.push(hidden("backupCodes", "backupCodes", backup_codes));
            custom = entry.custom_fields.clone();
            legacy = entry.legacy_fields.clone();
        }
        TaggedItem::Identity(identity) => {
            for (name, value) in [
                ("fullName", &identity.full_name),
                ("email", &identity.email),
                ("phone", &identity.phone),
                ("addressLine1", &identity.address_line1),
                ("addressLine2", &identity.address_line2),
                ("city", &identity.city),
                ("region", &identity.region),
                ("postalCode", &identity.postal_code),
                ("country", &identity.country),
            ] {
                fields.push(visible(name, value));
            }
            legacy = identity.legacy_fields.clone();
        }
        TaggedItem::SecureNote(note) => {
            if note.locked {
                fields.push(hidden("content", "content", is_present("content")));
            } else {
                fields.push(visible("content", &note.content));
            }
            legacy = note.legacy_fields.clone();
        }
        TaggedItem::Card(card) => {
            fields.push(visible("cardholderName", &card.cardholder_name));
            fields.push(visible("expiryMonth", &card.expiry_month));
            fields.push(visible("expiryYear", &card.expiry_year));
            fields.push(visible("brand", &card.brand));
            fields.push(visible("notes", &card.notes));
            fields.push(hidden("number", "number", is_present("number")));
            fields.push(hidden(
                "securityCode",
                "securityCode",
                is_present("securityCode"),
            ));
            legacy = card.legacy_fields.clone();
        }
        TaggedItem::WifiNetwork(network) => {
            fields.push(visible("ssid", &network.ssid));
            fields.push(visible("securityType", &network.security_type));
            fields.push(visible("notes", &network.notes));
            fields.push(hidden("password", "password", is_present("password")));
        }
        TaggedItem::SshKey(key) => {
            fields.push(visible("keyType", &key.key_type));
            fields.push(visible("publicKey", &key.public_key));
            fields.push(visible("notes", &key.notes));
            fields.push(hidden("privateKey", "privateKey", is_present("privateKey")));
            fields.push(hidden("passphrase", "passphrase", is_present("passphrase")));
        }
        TaggedItem::SoftwareLicense(license) => {
            fields.push(visible("productName", &license.product_name));
            fields.push(visible("purchasedFrom", &license.purchased_from));
            fields.push(visible("purchaseDate", &license.purchase_date));
            fields.push(visible("notes", &license.notes));
            fields.push(hidden("licenseKey", "licenseKey", is_present("licenseKey")));
        }
        TaggedItem::Document(document) => {
            fields.push(visible("documentType", &document.document_type));
            fields.push(visible("issuingAuthority", &document.issuing_authority));
            fields.push(visible("issueDate", &document.issue_date));
            fields.push(visible("expiryDate", &document.expiry_date));
            fields.push(visible("notes", &document.notes));
            fields.push(hidden(
                "documentNumber",
                "documentNumber",
                is_present("documentNumber"),
            ));
        }
        TaggedItem::CustomRecord(record) => {
            fields.push(visible("notes", &record.notes));
            custom = record.fields.clone();
        }
    }
    for (index, field) in custom.iter().enumerate() {
        let key = format!("field:{index}");
        let described = if field.kind == "secret" {
            hidden(&key, &key, is_present(&key))
        } else {
            DescribedField {
                key: key.clone(),
                ..visible(&key, &field.value)
            }
        };
        fields.push(labelled_field(described, &field.label));
    }
    for (index, field) in legacy.iter().enumerate() {
        let key = format!("legacy:{index}");
        let described = if field.secret {
            hidden(&key, &key, is_present(&key))
        } else {
            DescribedField {
                key: key.clone(),
                ..visible(&key, &field.value)
            }
        };
        fields.push(labelled_field(described, &field.label));
    }
    unconfusable(fields)
}

fn built_in_name(key: &str) -> Option<&'static str> {
    Some(match key {
        "username" => "Username",
        "email" => "Email",
        "url" => "Website",
        "notes" => "Notes",
        "recoveryEmail" => "Recovery email",
        "recoveryPhone" => "Recovery phone",
        "password" => "Password",
        "backupCodes" => "Backup codes",
        "fullName" => "Full name",
        "phone" => "Phone",
        "addressLine1" => "Address line 1",
        "addressLine2" => "Address line 2",
        "city" => "City",
        "region" => "Region",
        "postalCode" => "Postal code",
        "country" => "Country",
        "content" => "Note",
        "cardholderName" => "Cardholder name",
        "expiryMonth" => "Expiry month",
        "expiryYear" => "Expiry year",
        "brand" => "Brand",
        "number" => "Card number",
        "securityCode" => "Security code",
        "ssid" => "Network name",
        "securityType" => "Security type",
        "keyType" => "Key type",
        "publicKey" => "Public key",
        "privateKey" => "Private key",
        "passphrase" => "Passphrase",
        "productName" => "Product name",
        "purchasedFrom" => "Purchased from",
        "purchaseDate" => "Purchase date",
        "licenseKey" => "Licence key",
        "documentType" => "Document type",
        "issuingAuthority" => "Issuing authority",
        "issueDate" => "Issue date",
        "expiryDate" => "Expiry date",
        "documentNumber" => "Document number",
        _ => return None,
    })
}

fn display_name(field: &DescribedField) -> String {
    if let Some(name) = built_in_name(&field.key) {
        return name.to_string();
    }
    if field.name != field.key {
        return field.name.clone();
    }
    let position = |prefix: &str| {
        field
            .key
            .strip_prefix(prefix)
            .and_then(|index| index.parse::<usize>().ok())
            .map(|index| index + 1)
    };
    if let Some(number) = position("field:") {
        format!("Custom field {number}")
    } else if let Some(number) = position("legacy:") {
        format!("Older field {number}")
    } else {
        field.key.clone()
    }
}

fn find_index(fields: &[DescribedField], wanted: &str) -> Option<usize> {
    let wanted = wanted.trim();
    let lowered = wanted.to_lowercase();
    fields
        .iter()
        .position(|field| field.key == wanted)
        .or_else(|| {
            fields
                .iter()
                .position(|field| field.key.eq_ignore_ascii_case(wanted))
        })
        .or_else(|| {
            fields
                .iter()
                .position(|field| field.name.trim().to_lowercase() == lowered)
        })
}

fn find_field<'a>(fields: &'a [DescribedField], wanted: &str) -> Option<&'a DescribedField> {
    find_index(fields, wanted).map(|index| &fields[index])
}

fn chosen_fields(
    session: &crate::vault::UnlockedVault,
    chosen: &CliCandidate,
) -> Result<Vec<DescribedField>, Stop> {
    let opened = session
        .open_item(&chosen.id)
        .map_err(|_| Stop::Reply(CliErrorCode::NotFound))?;
    if opened.kind() != chosen.kind {
        return Err(Stop::Reply(CliErrorCode::NotFound));
    }
    Ok(described_fields(&opened))
}

enum Picked {
    Frames(Vec<CliReply>),
    Hidden(String),
}

fn release_error(error: &str) -> Stop {
    if error == PRESENCE_REQUIRED {
        Stop::ReplyWith(CliErrorCode::Cancelled, PRESENCE_MESSAGE)
    } else if error == EMPTY_FIELD_ERROR {
        Stop::Reply(CliErrorCode::EmptyField)
    } else if error == "Unlock your vault first." || error == VAULT_CHANGED {
        Stop::Reply(CliErrorCode::Stale)
    } else {
        Stop::Reply(CliErrorCode::Unavailable)
    }
}

#[derive(Clone, Copy)]
struct Freshness {
    epoch: u64,
    password_since: Option<Instant>,
}

fn release(
    context: &CliContext<'_>,
    request_id: &str,
    command: &CliCommand,
    chosen: Option<&CliCandidate>,
    freshness: Freshness,
) -> Result<Vec<CliReply>, Stop> {
    let epoch = freshness.epoch;
    match command {
        CliCommand::List => list_frames(context.vault, epoch, request_id, context.list_budget),
        CliCommand::Get { field: None, .. } => {
            let chosen = chosen.ok_or(Stop::Reply(CliErrorCode::NotFound))?;
            let fields = with_session(context.vault, epoch, |session| {
                chosen_fields(session, chosen)
            })?;
            let wire: Vec<CliField> = fields
                .iter()
                .filter(|field| field.present)
                .map(|field| CliField {
                    name: field.name.clone(),
                    hidden: field.hidden,
                    value: if field.hidden {
                        None
                    } else {
                        field.value.as_ref().map(|value| value.to_string())
                    },
                })
                .collect();
            let reply = CliReply::item(
                request_id,
                CliItemSummary {
                    id: chosen.id.clone(),
                    kind: chosen.kind.clone(),
                    title: chosen.title.clone(),
                },
                wire,
            );
            if !reply.fits_one_frame() {
                return Err(Stop::ReplyWith(CliErrorCode::TooLarge, ITEM_TOO_LARGE));
            }
            Ok(vec![reply])
        }
        CliCommand::Get {
            field: Some(name),
            copy,
            ..
        } => {
            let chosen = chosen.ok_or(Stop::Reply(CliErrorCode::NotFound))?;
            let picked = with_session(context.vault, epoch, |session| {
                let fields = chosen_fields(session, chosen)?;
                let field = find_field(&fields, name).ok_or(Stop::Reply(CliErrorCode::NoField))?;
                if field.hidden {
                    return Ok(Picked::Hidden(field.key.clone()));
                }
                let value = field
                    .value
                    .as_ref()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or(Stop::Reply(CliErrorCode::EmptyField))?;
                if *copy {
                    let seconds = context.approvals.clear_after_seconds();
                    context
                        .effects
                        .copy_secret(value.clone(), Some(seconds * 1_000))
                        .map_err(|_| Stop::Reply(CliErrorCode::Unavailable))?;
                    return Ok(Picked::Frames(vec![CliReply::copied(
                        request_id,
                        Some(seconds),
                    )]));
                }
                let reply = CliReply::value(request_id, value, false);
                if !reply.fits_one_frame() {
                    return Err(Stop::Reply(CliErrorCode::TooLarge));
                }
                Ok(Picked::Frames(vec![reply]))
            })?;
            match picked {
                Picked::Frames(frames) => Ok(frames),
                Picked::Hidden(key) => {
                    release_hidden(context, request_id, chosen, &key, *copy, freshness)
                }
            }
        }
        CliCommand::Totp { copy, .. } => {
            let chosen = chosen.ok_or(Stop::Reply(CliErrorCode::NotFound))?;
            with_session(context.vault, epoch, |session| {
                let (code, remaining) = terminal_totp_in_session(session, &chosen.id)
                    .map_err(|error| release_error(&error))?
                    .ok_or(Stop::Reply(CliErrorCode::NoTotp))?;
                if *copy {
                    let seconds = context.approvals.clear_after_seconds();
                    context
                        .effects
                        .copy_secret(code, Some(seconds * 1_000))
                        .map_err(|_| Stop::Reply(CliErrorCode::Unavailable))?;
                    record_terminal_release_in(
                        context.vault,
                        session,
                        EntryKind::Copy,
                        &chosen.id,
                        &chosen.kind,
                        "totp",
                    );
                    return Ok(vec![CliReply::copied(request_id, Some(seconds))]);
                }
                record_terminal_release_in(
                    context.vault,
                    session,
                    EntryKind::Reveal,
                    &chosen.id,
                    &chosen.kind,
                    "totp",
                );
                Ok(vec![CliReply::totp(
                    request_id,
                    &code,
                    remaining.clamp(1, MAX_TOTP_REMAINING_SECONDS),
                )])
            })
        }
    }
}

fn release_hidden(
    context: &CliContext<'_>,
    request_id: &str,
    chosen: &CliCandidate,
    key: &str,
    copy: bool,
    freshness: Freshness,
) -> Result<Vec<CliReply>, Stop> {
    if let Some(since) = freshness.password_since {
        context
            .presence
            .require_password_since(freshness.epoch, since)
            .map_err(|error| release_error(&error))?;
    }
    let wanted = TerminalField {
        epoch: freshness.epoch,
        id: &chosen.id,
        kind: &chosen.kind,
        field: key,
    };
    if copy {
        let seconds = context.approvals.clear_after_seconds();
        terminal_copy_item_field_in_state(
            context.vault,
            context.presence,
            context.effects,
            wanted,
            Some(seconds * 1_000),
        )
        .map_err(|error| release_error(&error))?;
        return Ok(vec![CliReply::copied(request_id, Some(seconds))]);
    }
    let value = terminal_item_field_in_state(context.vault, context.presence, wanted, &|value| {
        CliReply::value(request_id, value, true).fits_one_frame()
    })
    .map_err(|error| release_error(&error))?
    .ok_or(Stop::Reply(CliErrorCode::TooLarge))?;
    Ok(vec![CliReply::value(request_id, &value, true)])
}

fn list_frames(
    vault: &VaultState,
    epoch: u64,
    request_id: &str,
    total_budget: usize,
) -> Result<Vec<CliReply>, Stop> {
    let items = with_session(vault, epoch, |session| Ok(all_items(session)))?;
    let budget = MAX_CLI_REPLY_BYTES - FRAME_MARGIN_BYTES;
    let mut frames = Vec::new();
    let mut current = Vec::new();
    let mut size = 0;
    for item in items {
        let summary = CliItemSummary {
            id: item.id,
            kind: item.kind,
            title: bounded_title_text(&item.title),
        };
        let item_size = serde_json::to_vec(&summary)
            .map(|bytes| bytes.len() + 1)
            .map_err(|_| Stop::Reply(CliErrorCode::Unavailable))?;
        if !current.is_empty() && size + item_size > budget {
            frames.push(CliReply::items(request_id, std::mem::take(&mut current)));
            size = 0;
        }
        size += item_size;
        current.push(summary);
    }
    if !current.is_empty() || frames.is_empty() {
        frames.push(CliReply::items(request_id, current));
    }
    frames.push(CliReply::done(request_id));
    let mut total = 0_usize;
    for frame in &frames {
        let encoded = frame
            .to_bytes()
            .map_err(|_| Stop::Reply(CliErrorCode::Unavailable))?;
        total = total.saturating_add(encoded.len());
    }
    if total > total_budget {
        return Err(Stop::ReplyWith(CliErrorCode::TooLarge, LIST_TOO_LARGE));
    }
    Ok(frames)
}

#[cfg(test)]
pub(super) fn list_within(
    vault: &VaultState,
    request_id: &str,
    total_budget: usize,
) -> Result<Vec<CliReply>, (CliErrorCode, &'static str)> {
    list_frames(vault, vault.session_epoch(), request_id, total_budget).map_err(|stop| match stop {
        Stop::ReplyWith(code, message) => (code, message),
        Stop::Reply(code) => (code, ""),
        Stop::Gone => (CliErrorCode::Unavailable, ""),
    })
}

#[cfg(test)]
pub(super) fn release_at(
    context: &CliContext<'_>,
    payload: &[u8],
    chosen: Option<&CliCandidate>,
    epoch: u64,
) -> Result<Vec<CliReply>, CliErrorCode> {
    let (request_id, command) = parse_or_refuse(payload).map_err(|_| CliErrorCode::Invalid)?;
    release(
        context,
        &request_id,
        &command,
        chosen,
        Freshness {
            epoch,
            password_since: None,
        },
    )
    .map_err(|stop| match stop {
        Stop::Reply(code) | Stop::ReplyWith(code, _) => code,
        Stop::Gone => CliErrorCode::Unavailable,
    })
}
