use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::application::broker_tests::FakeClock;
use crate::application::tests::{Effect, FakeEffects};
use crate::browser_protocol::BrowserRequest;
use crate::cli_protocol::{
    parse_request, CliErrorCode, CliReply, CliReplyType, WaitReason, MAX_CLI_REPLY_BYTES,
    MAX_CLI_REQUEST_BYTES,
};
use crate::release::ReleasePresence;
use crate::test_support::{grant, TestVault};
use crate::vault::release_record::{EntryKind, Outcome};
use crate::vault::{CustomFieldEntry, VaultEntry};

use super::approval_slot::ApprovalSlot;
use super::browser_fill::NormalizedOrigin;
use super::browser_fill_broker::{ApprovalRequest, BrowserFillState};
use super::cli_broker::{
    CliApprovalRequestEvent, CliApprovalState, CliDecisionInput, CliDecisionKind,
    CliUnlockRequestEvent,
};
use super::cli_requests::{serve_cli_request, CliContext, CliHost};
use super::lifecycle::lock_and_notify;
use super::release_record::{release_record_page_in_state, ReleaseRecordQuery};
use super::terminal_allowances::{
    TerminalAllowances, TerminalKey, TerminalOrigin, UnverifiedProgram, ALLOWANCE_TTL,
};

const CANARY: &str = "fictional-password-canary";
const RFC_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[derive(Default)]
struct FakeHost {
    gone: AtomicBool,
    sent: Mutex<Vec<CliReply>>,
    events: Mutex<Vec<String>>,
}

impl FakeHost {
    fn sent(&self) -> Vec<CliReply> {
        self.sent.lock().expect("sent").clone()
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().expect("events").clone()
    }

    fn note(&self, event: String) {
        self.events.lock().expect("events").push(event);
    }
}

impl CliHost for FakeHost {
    fn peer_connected(&self) -> bool {
        !self.gone.load(Ordering::SeqCst)
    }

    fn send(&self, reply: &CliReply) -> bool {
        if self.gone.load(Ordering::SeqCst) {
            return false;
        }
        self.sent.lock().expect("sent").push(reply.clone());
        true
    }

    fn unlock_requested(&self, _event: &CliUnlockRequestEvent) {
        self.note("unlockRequested".to_string());
    }

    fn unlock_ended(&self, reason: &'static str) {
        self.note(format!("unlockEnded:{reason}"));
    }

    fn approval_requested(&self, _event: &CliApprovalRequestEvent) {
        self.note("approvalRequested".to_string());
    }

    fn approval_cancelled(&self, _approval_id: &str, reason: &'static str) {
        self.note(format!("approvalCancelled:{reason}"));
    }

    fn allowances_changed(&self) {
        self.note("allowancesChanged".to_string());
    }
}

struct Harness {
    vault: TestVault,
    presence: ReleasePresence,
    slot: ApprovalSlot,
    approvals: CliApprovalState,
    allowances: TerminalAllowances,
    clock: Arc<FakeClock>,
    unlock_timeout: Duration,
}

impl Harness {
    fn new() -> Self {
        Self::build(false)
    }

    fn without_allowance_epoch_check() -> Self {
        Self::build(true)
    }

    fn build(skip_epoch: bool) -> Self {
        let vault = TestVault::with_login("fictional-login", "https://northwind.example");
        vault.seed(|payload| {
            let entry = &mut payload.entries[0];
            entry.title = "Northwind mail".to_string();
            entry.username = "casey@northwind.example".to_string();
            entry.password = CANARY.to_string();
            entry.totp = Some(RFC_KEY.to_string());
            entry.custom_fields = vec![
                CustomFieldEntry {
                    label: "Member number".to_string(),
                    value: "fictional-member-4471".to_string(),
                    kind: "text".to_string(),
                },
                CustomFieldEntry {
                    label: "Security answer".to_string(),
                    value: format!("{CANARY}-answer"),
                    kind: "secret".to_string(),
                },
            ];
        });
        let clock = FakeClock::new();
        let slot = ApprovalSlot::default();
        Self {
            vault,
            presence: ReleasePresence::default(),
            approvals: CliApprovalState::with_clock(slot.clone(), clock.clone()),
            allowances: if skip_epoch {
                TerminalAllowances::without_epoch_check(clock.clone())
            } else {
                TerminalAllowances::with_clock(clock.clone())
            },
            slot,
            clock,
            unlock_timeout: Duration::from_secs(10),
        }
    }

    fn effects(&self) -> FakeEffects<'_> {
        FakeEffects::with_allowances(
            self.vault.path().to_path_buf(),
            &self.presence,
            &self.allowances,
        )
    }

    fn serve(
        &self,
        host: &FakeHost,
        effects: &FakeEffects<'_>,
        payload: &[u8],
        origin: &TerminalOrigin,
    ) {
        let mut context = CliContext::new(
            &self.vault.state,
            &self.presence,
            effects,
            &self.approvals,
            &self.allowances,
            host,
        );
        context.poll = Duration::from_millis(10);
        context.unlock_timeout = self.unlock_timeout;
        serve_cli_request(&context, payload, origin);
    }

    fn run(&self, payload: &[u8], origin: &TerminalOrigin) -> Vec<CliReply> {
        let host = FakeHost::default();
        let effects = self.effects();
        self.serve(&host, &effects, payload, origin);
        host.sent()
    }

    fn run_with(
        &self,
        payload: &[u8],
        origin: &TerminalOrigin,
        act: impl FnOnce(&FakeHost, &FakeEffects<'_>),
    ) -> (Vec<CliReply>, Vec<String>) {
        let host = FakeHost::default();
        let effects = self.effects();
        std::thread::scope(|scope| {
            scope.spawn(|| self.serve(&host, &effects, payload, origin));
            act(&host, &effects);
        });
        (host.sent(), host.events())
    }

    fn pending(&self) -> CliApprovalRequestEvent {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(event) = self.approvals.pending_request() {
                return event;
            }
            assert!(Instant::now() < until, "no approval was shown");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn decide(
        &self,
        event: &CliApprovalRequestEvent,
        decision: CliDecisionKind,
        item_id: Option<&str>,
        allow_terminal: bool,
    ) -> Result<(), &'static str> {
        self.approvals.window_focus_changed(true);
        self.clock.advance(Duration::from_secs(1));
        self.approvals.decide(CliDecisionInput {
            approval_id: event.approval_id.clone(),
            decision,
            item_id: item_id.map(str::to_string),
            allow_terminal: Some(allow_terminal),
            clear_after_seconds: None,
        })
    }

    fn allow(&self, allow_terminal: bool) {
        let event = self.pending();
        self.decide(&event, CliDecisionKind::Allow, None, allow_terminal)
            .expect("allowed");
    }

    fn deny(&self) {
        let event = self.pending();
        self.decide(&event, CliDecisionKind::Deny, None, false)
            .expect("denied");
    }

    fn lock(&self, effects: &FakeEffects<'_>) {
        lock_and_notify(&self.vault.state, effects).expect("locked");
    }
}

fn wait_for(host: &FakeHost, event: &str) {
    let until = Instant::now() + Duration::from_secs(5);
    while !host.events().iter().any(|seen| seen == event) {
        assert!(Instant::now() < until, "{event} never happened");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn id(n: u8) -> String {
    format!("{n:02x}").repeat(16)
}

fn request(n: u8, value: serde_json::Value) -> Vec<u8> {
    let mut value = value;
    value["version"] = serde_json::json!(1);
    value["requestId"] = serde_json::json!(id(n));
    serde_json::to_vec(&value).expect("encodes")
}

fn get(n: u8, field: Option<&str>, copy: bool) -> Vec<u8> {
    let mut value = serde_json::json!({ "type": "get", "item": "northwind MAIL " });
    if let Some(field) = field {
        value["field"] = serde_json::json!(field);
    }
    if copy {
        value["copy"] = serde_json::json!(true);
    }
    request(n, value)
}

fn terminal(leader_started: u64) -> TerminalOrigin {
    TerminalOrigin {
        key: Some(TerminalKey::controlling(34_819, 4_101, leader_started)),
        device: Some("pts/3".to_string()),
        program: Some(UnverifiedProgram::reported("bash".to_string())),
        remote: false,
    }
}

fn error_code(replies: &[CliReply]) -> Option<CliErrorCode> {
    replies.last().and_then(CliReply::error_code)
}

fn wire(replies: &[CliReply]) -> String {
    replies
        .iter()
        .map(|reply| String::from_utf8(reply.to_bytes().expect("encodes").to_vec()).expect("utf8"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn allow_terminal_for_five_minutes(harness: &Harness, origin: &TerminalOrigin) {
    let (replies, _) = harness.run_with(&get(200, Some("username"), false), origin, |_, _| {
        harness.allow(true)
    });
    assert_eq!(
        replies
            .last()
            .and_then(|reply| reply.value.clone())
            .as_deref(),
        Some("casey@northwind.example")
    );
}

fn record_entries(harness: &Harness) -> Vec<super::release_record::ReleaseEntryView> {
    release_record_page_in_state(
        &harness.vault.state,
        ReleaseRecordQuery {
            limit: Some(1_000),
            ..ReleaseRecordQuery::default()
        },
    )
    .expect("record page")
    .entries
}

#[test]
fn malformed_oversized_and_empty_requests_are_refused_as_invalid() {
    let harness = Harness::new();
    let origin = terminal(100);
    for payload in [
        b"not json".to_vec(),
        Vec::new(),
        vec![b' '; MAX_CLI_REQUEST_BYTES + 1],
        request(
            1,
            serde_json::json!({ "type": "get", "item": "Northwind mail", "origin": "https://northwind.example" }),
        ),
    ] {
        let replies = harness.run(&payload, &origin);
        assert_eq!(replies.len(), 1);
        assert_eq!(error_code(&replies), Some(CliErrorCode::Invalid));
    }
    assert!(harness.approvals.pending_request().is_none());
}

#[test]
fn a_replayed_request_id_is_stale() {
    let harness = Harness::new();
    let origin = terminal(100);
    let (first, _) = harness.run_with(&get(2, None, false), &origin, |_, _| harness.deny());
    assert_eq!(error_code(&first), Some(CliErrorCode::Cancelled));

    let replayed = harness.run(&get(2, None, false), &origin);
    assert_eq!(error_code(&replayed), Some(CliErrorCode::Stale));
    assert!(harness.approvals.pending_request().is_none());
}

#[test]
fn a_second_request_while_one_is_pending_is_busy_at_once() {
    let harness = Harness::new();
    let origin = terminal(100);
    let (first, _) = harness.run_with(&get(3, None, false), &origin, |_, _| {
        harness.pending();
        let second = harness.run(&get(4, None, false), &origin);
        assert_eq!(second.len(), 1);
        assert_eq!(error_code(&second), Some(CliErrorCode::Busy));
        harness.deny();
    });
    assert_eq!(error_code(&first), Some(CliErrorCode::Cancelled));
}

#[test]
fn a_request_while_locked_waits_for_the_unlock_and_then_still_asks() {
    let harness = Harness::new();
    let origin = terminal(100);
    grant(&harness.vault, &harness.presence);
    harness.lock(&harness.effects());

    let (replies, events) =
        harness.run_with(&get(5, Some("password"), false), &origin, |host, _| {
            wait_for(host, "unlockRequested");
            assert!(harness.approvals.pending_request().is_none());
            harness.vault.reopen();
            let event = harness.pending();
            assert_eq!(event.candidates.len(), 1);
            harness.deny();
        });

    assert_eq!(replies[0], CliReply::waiting(&id(5), WaitReason::Unlock));
    assert_eq!(replies[1], CliReply::waiting(&id(5), WaitReason::Approval));
    assert_eq!(error_code(&replies), Some(CliErrorCode::Cancelled));
    assert!(events.contains(&"unlockEnded:unlocked".to_string()));
    assert!(!wire(&replies).contains(CANARY));
}

#[test]
fn an_unlock_that_never_comes_ends_at_the_deadline() {
    let mut harness = Harness::new();
    harness.unlock_timeout = Duration::from_millis(150);
    harness.lock(&harness.effects());

    let replies = harness.run(&get(6, Some("password"), false), &terminal(100));

    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0], CliReply::waiting(&id(6), WaitReason::Unlock));
    assert_eq!(error_code(&replies), Some(CliErrorCode::Timeout));
}

#[test]
fn a_lock_between_the_unlock_and_the_answer_is_stale() {
    let harness = Harness::new();
    harness.lock(&harness.effects());

    let (replies, events) = harness.run_with(
        &get(7, Some("username"), false),
        &terminal(100),
        |host, effects| {
            wait_for(host, "unlockRequested");
            harness.vault.reopen();
            harness.pending();
            harness.lock(effects);
        },
    );

    assert_eq!(error_code(&replies), Some(CliErrorCode::Stale));
    assert!(events.contains(&"approvalCancelled:vaultChanged".to_string()));
    assert!(harness.approvals.pending_request().is_none());
}

#[test]
fn a_lock_during_a_pending_approval_is_stale_and_its_decision_expires() {
    let harness = Harness::new();
    let mut late_event = None;
    let (replies, _) = harness.run_with(
        &get(8, Some("username"), false),
        &terminal(100),
        |_, effects| {
            let event = harness.pending();
            harness.lock(effects);
            late_event = Some(event);
        },
    );
    assert_eq!(error_code(&replies), Some(CliErrorCode::Stale));
    let late_event = late_event.expect("an approval was shown");
    assert_eq!(
        harness.decide(&late_event, CliDecisionKind::Allow, None, false),
        Err("approvalExpired")
    );
}

#[test]
fn an_allowance_skips_the_click_and_lists_the_request() {
    let harness = Harness::new();
    let origin = terminal(100);
    allow_terminal_for_five_minutes(&harness, &origin);

    let replies = harness.run(&get(9, Some("Member number"), false), &origin);

    assert_eq!(replies.len(), 1);
    assert_eq!(
        replies[0],
        CliReply::value(&id(9), "fictional-member-4471", false)
    );
    let listed = harness.allowances.list(harness.vault.state.session_epoch());
    assert_eq!(listed.allowances.len(), 1);
    assert_eq!(listed.requests.len(), 1);
    assert_eq!(listed.requests[0].field.as_deref(), Some("Member number"));
    assert_eq!(listed.requests[0].terminal, "pts/3");
}

fn assert_needs_a_new_approval(harness: &Harness, origin: &TerminalOrigin, n: u8) {
    let (replies, _) = harness.run_with(&get(n, Some("username"), false), origin, |_, _| {
        let event = harness.pending();
        assert!(!event.allowed);
        harness.deny();
    });
    assert_eq!(error_code(&replies), Some(CliErrorCode::Cancelled));
}

#[test]
fn an_allowance_used_after_a_lock_and_unlock_needs_a_new_approval() {
    let harness = Harness::new();
    let origin = terminal(100);
    allow_terminal_for_five_minutes(&harness, &origin);

    harness.lock(&harness.effects());
    harness.vault.reopen();

    assert_needs_a_new_approval(&harness, &origin, 10);
    assert!(harness
        .allowances
        .list(harness.vault.state.session_epoch())
        .requests
        .is_empty());
}

#[test]
fn the_clearing_on_lock_alone_ends_an_allowance() {
    let harness = Harness::without_allowance_epoch_check();
    let origin = terminal(100);
    allow_terminal_for_five_minutes(&harness, &origin);

    let effects = harness.effects();
    harness.lock(&effects);
    harness.vault.reopen();

    assert!(effects.calls().contains(&Effect::ForgetTerminalAllowances));
    assert_needs_a_new_approval(&harness, &origin, 11);
}

#[test]
fn the_epoch_check_alone_ends_an_allowance_when_the_vault_changes_without_a_lock() {
    let harness = Harness::new();
    let origin = terminal(100);
    allow_terminal_for_five_minutes(&harness, &origin);

    harness.vault.reopen();

    assert_needs_a_new_approval(&harness, &origin, 12);
}

#[test]
fn an_allowance_ends_after_five_minutes_and_with_its_session_leader() {
    let clock = FakeClock::new();
    let allowances = TerminalAllowances::with_clock(clock.clone());
    let origin = terminal(100);
    assert!(allowances.grant(&origin, 4));
    clock.advance(ALLOWANCE_TTL - Duration::from_secs(1));
    assert!(allowances.covers(&origin, 4));
    assert!(!allowances.covers(&terminal(101), 4));
    assert!(!allowances.covers(&origin, 5));
    clock.advance(Duration::from_secs(2));
    assert!(!allowances.covers(&origin, 4));
}

#[test]
fn a_request_with_no_terminal_never_offers_or_uses_an_allowance() {
    let harness = Harness::new();
    let origin = TerminalOrigin::without_terminal();
    assert!(!harness
        .allowances
        .grant(&origin, harness.vault.state.session_epoch()));

    let (replies, _) = harness.run_with(&get(13, Some("username"), false), &origin, |_, _| {
        let event = harness.pending();
        assert!(!event.can_allow_terminal);
        assert_eq!(event.terminal, None);
        harness
            .decide(&event, CliDecisionKind::Allow, None, true)
            .expect("allowed");
    });
    assert_eq!(
        replies
            .last()
            .and_then(|reply| reply.value.clone())
            .as_deref(),
        Some("casey@northwind.example")
    );
    assert!(harness
        .allowances
        .list(harness.vault.state.session_epoch())
        .allowances
        .is_empty());
    assert_needs_a_new_approval(&harness, &origin, 14);
}

#[test]
fn an_allowance_with_lapsed_presence_asks_for_the_master_password_and_a_denial_cancels() {
    let harness = Harness::new();
    let origin = terminal(100);
    allow_terminal_for_five_minutes(&harness, &origin);

    let (replies, _) = harness.run_with(&get(15, Some("password"), false), &origin, |_, _| {
        let event = harness.pending();
        assert!(event.allowed);
        assert!(event.needs_presence);
        assert!(event.field_hidden);
        harness.deny();
    });

    assert_eq!(error_code(&replies), Some(CliErrorCode::Cancelled));
    assert!(!wire(&replies).contains(CANARY));
}

#[test]
fn an_approval_without_presence_still_releases_no_hidden_value() {
    let harness = Harness::new();
    let (replies, _) =
        harness.run_with(&get(16, Some("password"), false), &terminal(100), |_, _| {
            harness.allow(false)
        });
    assert_eq!(error_code(&replies), Some(CliErrorCode::Cancelled));
    assert!(!wire(&replies).contains(CANARY));
    assert!(record_entries(&harness).is_empty());
}

#[test]
fn presence_without_an_allowance_still_shows_the_approval_and_the_release_is_recorded() {
    let harness = Harness::new();
    grant(&harness.vault, &harness.presence);
    let (replies, _) =
        harness.run_with(&get(17, Some("password"), false), &terminal(100), |_, _| {
            let event = harness.pending();
            assert!(!event.needs_presence);
            assert!(!event.allowed);
            harness.allow(false);
        });

    assert_eq!(
        replies.last(),
        Some(&CliReply::value(&id(17), CANARY, true))
    );
    let entries = record_entries(&harness);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, EntryKind::Reveal);
    assert_eq!(entries[0].outcome, Outcome::Released);
    assert_eq!(entries[0].host.as_deref(), Some("terminal"));
    assert_eq!(entries[0].item_id.as_deref(), Some("fictional-login"));
}

#[test]
fn a_copied_value_never_crosses_the_channel_and_is_recorded_as_a_copy() {
    let harness = Harness::new();
    grant(&harness.vault, &harness.presence);
    let effects_calls = Mutex::new(Vec::new());
    let (replies, _) = harness.run_with(
        &get(18, Some("password"), true),
        &terminal(100),
        |_, effects| {
            harness.allow(false);
            let until = Instant::now() + Duration::from_secs(5);
            while !effects
                .calls()
                .iter()
                .any(|call| matches!(call, Effect::CopySecret { .. }))
            {
                assert!(Instant::now() < until);
                std::thread::sleep(Duration::from_millis(5));
            }
            *effects_calls.lock().expect("calls") = effects.calls();
        },
    );

    assert_eq!(replies.last(), Some(&CliReply::copied(&id(18), Some(30))));
    assert!(!wire(&replies).contains(CANARY));
    assert!(effects_calls
        .lock()
        .expect("calls")
        .contains(&Effect::CopySecret {
            value: CANARY.to_string(),
            clear_after_ms: Some(30_000),
        }));
    let entries = record_entries(&harness);
    assert_eq!(entries[0].kind, EntryKind::Copy);
    assert_eq!(entries[0].host.as_deref(), Some("terminal"));
}

#[test]
fn a_whole_item_names_hidden_fields_without_their_values() {
    let harness = Harness::new();
    let (replies, _) = harness.run_with(&get(19, None, false), &terminal(100), |_, _| {
        harness.allow(false)
    });
    let item = replies.last().expect("an item reply");
    assert_eq!(item.reply_type, CliReplyType::Item);
    let fields = item.fields.clone().expect("fields");
    let password = fields
        .iter()
        .find(|field| field.name == "password")
        .expect("password listed");
    assert!(password.hidden);
    assert_eq!(password.value, None);
    assert!(fields
        .iter()
        .any(|field| field.name == "Security answer" && field.hidden));
    assert!(!wire(&replies).contains(CANARY));
    assert!(!wire(&replies).contains(RFC_KEY));
}

#[test]
fn not_found_arrives_only_after_the_person_saw_it() {
    let harness = Harness::new();
    let origin = terminal(100);
    let missing = request(20, serde_json::json!({ "type": "get", "item": "Northwnd" }));
    let (replies, _) = harness.run_with(&missing, &origin, |host, _| {
        let event = harness.pending();
        assert_eq!(event.not_found.as_deref(), Some("Northwnd"));
        assert!(event.candidates.is_empty());
        assert!(!event.can_allow_terminal);
        assert!(host
            .sent()
            .iter()
            .all(|reply| reply.reply_type == CliReplyType::Waiting));
        harness
            .decide(&event, CliDecisionKind::Dismiss, None, false)
            .expect("dismissed");
    });
    assert_eq!(error_code(&replies), Some(CliErrorCode::NotFound));

    allow_terminal_for_five_minutes(&harness, &origin);
    let missing = request(21, serde_json::json!({ "type": "get", "item": "Northwnd" }));
    assert_eq!(
        error_code(&harness.run(&missing, &origin)),
        Some(CliErrorCode::NotFound)
    );
}

#[test]
fn several_matches_open_the_chooser_and_refuse_an_item_it_did_not_offer() {
    let harness = Harness::new();
    let origin = terminal(100);
    harness.vault.seed(|payload| {
        let mut twin = VaultEntry::default();
        twin.id = "fictional-twin".to_string();
        twin.title = "Northwind Mail".to_string();
        twin.username = "robin@northwind.example".to_string();
        payload.entries.push(twin);
        let mut other = VaultEntry::default();
        other.id = "fictional-other".to_string();
        other.title = "Contoso".to_string();
        payload.entries.push(other);
    });
    allow_terminal_for_five_minutes_on(&harness, &origin);

    let (replies, _) = harness.run_with(&get(22, Some("username"), false), &origin, |_, _| {
        let event = harness.pending();
        assert_eq!(event.candidates.len(), 2);
        assert!(event.allowed);
        assert_eq!(
            harness.decide(
                &event,
                CliDecisionKind::Allow,
                Some("fictional-other"),
                false
            ),
            Err("selectionNotOffered")
        );
    });
    assert_eq!(error_code(&replies), Some(CliErrorCode::Cancelled));

    let (replies, _) = harness.run_with(&get(23, Some("username"), false), &origin, |_, _| {
        let event = harness.pending();
        harness
            .decide(
                &event,
                CliDecisionKind::Allow,
                Some("fictional-twin"),
                false,
            )
            .expect("chosen");
    });
    assert_eq!(
        replies
            .last()
            .and_then(|reply| reply.value.clone())
            .as_deref(),
        Some("robin@northwind.example")
    );
}

fn allow_terminal_for_five_minutes_on(harness: &Harness, origin: &TerminalOrigin) {
    let by_id = request(
        201,
        serde_json::json!({ "type": "get", "item": "fictional-login", "field": "username" }),
    );
    harness.run_with(&by_id, origin, |_, _| harness.allow(true));
    assert!(harness
        .allowances
        .covers(origin, harness.vault.state.session_epoch()));
}

#[test]
fn a_closed_terminal_ends_the_approval_without_an_answer() {
    let harness = Harness::new();
    let (replies, events) = harness.run_with(
        &get(24, Some("username"), false),
        &terminal(100),
        |host, _| {
            harness.pending();
            host.gone.store(true, Ordering::SeqCst);
        },
    );
    assert_eq!(
        replies,
        vec![CliReply::waiting(&id(24), WaitReason::Approval)]
    );
    assert!(events.contains(&"approvalCancelled:connectionClosed".to_string()));
    assert!(harness.approvals.pending_request().is_none());
    assert!(!harness.slot.is_taken());
}

#[test]
fn an_unanswered_approval_times_out() {
    let harness = Harness::new();
    harness
        .approvals
        .shorten_approval_timeout(Duration::from_millis(150));
    let (replies, events) =
        harness.run_with(&get(25, Some("username"), false), &terminal(100), |_, _| {});
    assert_eq!(error_code(&replies), Some(CliErrorCode::Timeout));
    assert!(events.contains(&"approvalCancelled:expired".to_string()));
}

#[test]
fn a_browser_approval_makes_the_tool_busy_and_a_tool_approval_makes_the_browser_wait() {
    let harness = Harness::new();
    let browser = BrowserFillState::sharing(harness.slot.clone());
    let origin = NormalizedOrigin::from_request("https://northwind.example").expect("origin");
    let held = browser
        .begin(
            "fill-1",
            origin.clone(),
            harness.vault.state.session_epoch(),
            ApprovalRequest::Create,
        )
        .expect("a browser approval");

    let replies = harness.run(&get(26, Some("username"), false), &terminal(100));
    assert_eq!(error_code(&replies), Some(CliErrorCode::Busy));
    browser.revoke(&held.0);

    let (replies, _) =
        harness.run_with(&get(27, Some("username"), false), &terminal(100), |_, _| {
            harness.pending();
            assert_eq!(
                browser
                    .begin(
                        "fill-2",
                        origin.clone(),
                        harness.vault.state.session_epoch(),
                        ApprovalRequest::Create
                    )
                    .err(),
                Some("approvalUnavailable")
            );
            harness.deny();
        });
    assert_eq!(error_code(&replies), Some(CliErrorCode::Cancelled));
    assert!(browser
        .begin(
            "fill-3",
            origin,
            harness.vault.state.session_epoch(),
            ApprovalRequest::Create
        )
        .is_ok());
}

#[test]
fn a_browser_request_is_invalid_on_the_tool_channel_and_the_reverse() {
    let browser = serde_json::json!({
        "version": 1, "type": "capabilities", "requestId": id(28)
    });
    let refused =
        parse_request(&serde_json::to_vec(&browser).expect("encodes")).expect_err("refused");
    assert_eq!(refused.code, CliErrorCode::Invalid);
    let fill = serde_json::json!({
        "version": 5, "type": "fill", "requestId": "fill-5-1", "origin": "https://northwind.example"
    });
    assert!(parse_request(&serde_json::to_vec(&fill).expect("encodes")).is_err());

    let tool = serde_json::json!({
        "version": 1, "type": "get", "requestId": id(29), "item": "Northwind mail", "field": "password"
    });
    assert!(serde_json::from_value::<BrowserRequest>(tool.clone())
        .map(|request| request.validate())
        .unwrap_or(false)
        .eq(&false));
    let tool_list = serde_json::json!({ "version": 1, "type": "list", "requestId": id(30) });
    assert!(!serde_json::from_value::<BrowserRequest>(tool_list)
        .map(|request| request.validate())
        .unwrap_or(false));
}

#[test]
fn a_totp_request_returns_a_bounded_code_and_records_it() {
    let harness = Harness::new();
    let totp = request(
        31,
        serde_json::json!({ "type": "totp", "item": "Northwind mail" }),
    );
    let (replies, _) = harness.run_with(&totp, &terminal(100), |_, _| harness.allow(false));
    let reply = replies.last().expect("a reply");
    assert_eq!(reply.reply_type, CliReplyType::Totp);
    let code = reply.code.clone().expect("a code");
    assert!(code.len() <= 9 && code.bytes().all(|byte| byte.is_ascii_digit()));
    assert!(!wire(&replies).contains(RFC_KEY));
    let entries = record_entries(&harness);
    assert_eq!(entries[0].kind, EntryKind::Reveal);
    assert_eq!(entries[0].host.as_deref(), Some("terminal"));
}

#[test]
fn a_long_list_arrives_in_frames_that_each_fit() {
    let harness = Harness::new();
    harness.vault.seed(|payload| {
        for index in 0..400 {
            let mut entry = VaultEntry::default();
            entry.id = format!("fictional-{index:04}");
            entry.title = format!("Fictional service {index} {}", "x".repeat(300));
            payload.entries.push(entry);
        }
    });
    let list = request(32, serde_json::json!({ "type": "list" }));
    let (replies, _) = harness.run_with(&list, &terminal(100), |_, _| harness.allow(false));

    let frames: Vec<&CliReply> = replies
        .iter()
        .filter(|reply| reply.reply_type == CliReplyType::Items)
        .collect();
    assert!(frames.len() > 1);
    for reply in &replies {
        assert!(reply.to_bytes().expect("encodes").len() <= MAX_CLI_REPLY_BYTES);
    }
    let listed: usize = frames
        .iter()
        .map(|reply| reply.items.as_ref().map_or(0, Vec::len))
        .sum();
    assert_eq!(listed, 401);
    assert_eq!(
        replies.last().map(|reply| reply.reply_type),
        Some(CliReplyType::Done)
    );
}
