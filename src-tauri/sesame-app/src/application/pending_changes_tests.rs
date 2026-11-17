use crate::application::broker_tests::{let_delay_pass, state_with_clock};
use crate::application::tests::{Effect, FakeEffects};
use crate::browser_protocol::{BrowserRequest, BrowserResponse, PENDING_PASSWORD_PROTOCOL_VERSION};
use crate::test_support::TestVault;
use crate::vault::history::HISTORY_RETENTION_SECONDS;
use crate::vault::pending_change::{
    pending_path, read_pending, write_pending, FillState, PendingKind, HANDLE_LIFETIME_SECS,
};
use crate::vault::util::unix_timestamp;
use crate::vault::{MatchRule, TaggedItem, VaultEntry};

use super::browser_fill::{ApprovalDecision, ApprovalKind};
use super::browser_fill_broker::{ApprovalEvent, BrowserFillState};
use super::browser_replies::BrowserReply;
use super::pending_changes::{
    change_response_in_state, complete_change_in_state, complete_create_in_state,
    create_response_in_state, discard_pending_login_in_state, go_back_pending_change_in_state,
    keep_pending_change_in_state, list_pending_changes_in_state, pending_response_in_state,
};

const OLD_PASSWORD: &str = "fictional-stored-secret";
const ORIGIN: &str = "https://example.com";

fn request(message_type: &str, origin: &str) -> BrowserRequest {
    BrowserRequest {
        version: PENDING_PASSWORD_PROTOCOL_VERSION,
        message_type: message_type.to_string(),
        request_id: format!("{message_type}-1"),
        origin: Some(origin.to_string()),
        fields: None,
        username: None,
        password: None,
        title: None,
        kind: None,
        style: Some("characters".to_string()),
        size: Some(20),
        handle: None,
        action: None,
    }
}

fn pending(handle: &str, action: &str, origin: &str) -> BrowserRequest {
    let mut request = request("pending", origin);
    request.style = None;
    request.size = None;
    request.handle = Some(handle.to_string());
    request.action = Some(action.to_string());
    request
}

fn wire(response: &BrowserResponse) -> String {
    String::from_utf8(response.to_zeroizing_bytes().expect("encodes").to_vec()).expect("utf8")
}

fn live_password(vault: &TestVault, id: &str) -> String {
    let session = vault.state.session.lock().expect("session lock");
    let session = session.as_ref().expect("session");
    let payload = session.open_payload().expect("payload");
    payload
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .expect("login")
        .password
        .clone()
}

fn history_passwords(vault: &TestVault, id: &str) -> Vec<String> {
    let session = vault.state.session.lock().expect("session lock");
    let session = session.as_ref().expect("session");
    let payload = session.open_payload().expect("payload");
    payload
        .history
        .iter()
        .filter_map(|entry| match &entry.item {
            TaggedItem::Login(login) if login.id == id => Some(login.password.clone()),
            _ => None,
        })
        .collect()
}

fn approved_change(vault: &TestVault) -> BrowserResponse {
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = request("change", ORIGIN);
    let offer = match change_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(response) => panic!("no approval: {:?}", response.reason),
    };
    let_delay_pass(&state, &clock);
    state
        .decide(
            offer.approval.approval_id(),
            ApprovalDecision::Selected("login-a".to_string()),
        )
        .expect("approved");
    let decision = offer.receiver.recv().expect("decision");
    complete_change_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    )
}

fn approved_create(vault: &TestVault, origin: &str) -> BrowserResponse {
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = request("create", origin);
    let offer = match create_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(response) => panic!("no approval: {:?}", response.reason),
    };
    let_delay_pass(&state, &clock);
    state
        .decide(offer.approval.approval_id(), ApprovalDecision::Approved)
        .expect("approved");
    let decision = offer.receiver.recv().expect("decision");
    complete_create_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    )
}

fn report(vault: &TestVault, handle: &str, action: &str) -> BrowserResponse {
    pending_response_in_state(&vault.state, &pending(handle, action, ORIGIN))
}

fn rewrite_created_at(vault: &TestVault, age: u64) {
    let session = vault.state.session.lock().expect("session lock");
    let session = session.as_ref().expect("session");
    let mut changes = read_pending(session).expect("pending list");
    for change in &mut changes {
        change.created_at = unix_timestamp().saturating_sub(age);
    }
    write_pending(session, &changes).expect("written");
}

#[test]
fn a_change_opens_an_approval_and_writes_nothing_before_it() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = request("change", ORIGIN);
    assert!(request.validate());

    let offer = match change_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no change approval was offered"),
    };

    let ApprovalEvent::Change(event) = offer.approval.event() else {
        panic!("not a change approval");
    };
    assert_eq!(event.hostname, "example.com");
    assert_eq!(event.candidates.len(), 1);
    assert_eq!(event.candidates[0].id, "login-a");
    assert!(event.unconfirmed.is_empty());
    assert_eq!(live_password(&vault, "login-a"), OLD_PASSWORD);
    assert!(!pending_path(vault.path()).exists());
    assert_eq!(
        state.pending_change_request().map(|event| event.hostname),
        Some("example.com".to_string())
    );
}

#[test]
fn an_approved_change_saves_the_new_password_and_keeps_the_old_one_in_history() {
    let vault = TestVault::with_login("login-a", ORIGIN);

    let response = approved_change(&vault);

    assert_eq!(response.message_type, "changed");
    assert_eq!(response.current_password.as_deref(), Some(OLD_PASSWORD));
    let new_password = response.new_password.clone().expect("new password");
    assert_eq!(new_password.chars().count(), 20);
    assert_ne!(new_password, OLD_PASSWORD);
    assert_eq!(response.match_kind.as_deref(), Some("exact"));
    let request = request("change", ORIGIN);
    assert!(response.validate_for(&request));
    assert_eq!(live_password(&vault, "login-a"), new_password);
    assert_eq!(vault.stored_login("login-a").password, new_password);
    assert_eq!(
        history_passwords(&vault, "login-a"),
        vec![OLD_PASSWORD.to_string()]
    );

    let handle = response.handle.clone().expect("handle");
    let file = std::fs::read(pending_path(vault.path())).expect("pending file");
    let text = String::from_utf8_lossy(&file);
    assert!(!text.contains(&new_password));
    assert!(!text.contains(OLD_PASSWORD));
    assert!(!text.contains(&handle));

    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert_eq!(list.changes.len(), 1);
    let view = &list.changes[0];
    assert_eq!(view.kind, PendingKind::Change);
    assert_eq!(view.host, "example.com");
    assert_eq!(view.fill, FillState::Unknown);
    assert!(view.can_go_back);
    assert_eq!(view.days_left, Some(30));
    assert!(!view.urgent);
}

#[test]
fn a_change_and_a_create_each_record_one_activity_entry() {
    use crate::vault::release_record::{EntryKind, Outcome};
    let vault = TestVault::with_login("login-a", ORIGIN);
    {
        let session = vault.state.session.lock().expect("session lock");
        vault
            .state
            .release_record
            .open(session.as_ref().expect("session"))
            .expect("record opened");
    }
    approved_change(&vault);
    approved_create(&vault, "https://signup.example.net");
    let session = vault.state.session.lock().expect("session lock");
    let entries = vault
        .state
        .release_record
        .entries(session.as_ref().expect("session"))
        .expect("entries");
    let changed: Vec<_> = entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::BrowserChange)
        .collect();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].outcome, Outcome::Updated);
    assert_eq!(changed[0].item_id.as_deref(), Some("login-a"));
    let created: Vec<_> = entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::BrowserCreate)
        .collect();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].outcome, Outcome::Saved);
}

#[test]
fn a_denied_change_writes_nothing() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = request("change", ORIGIN);
    let offer = match change_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no approval"),
    };
    let_delay_pass(&state, &clock);
    state
        .decide(offer.approval.approval_id(), ApprovalDecision::Denied)
        .expect("denied");
    let decision = offer.receiver.recv().expect("decision");

    let response = complete_change_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    );

    assert_eq!(response.message_type, "change-unavailable");
    assert_eq!(response.reason.as_deref(), Some("approvalDeclined"));
    assert!(!wire(&response).contains(OLD_PASSWORD));
    assert_eq!(live_password(&vault, "login-a"), OLD_PASSWORD);
    assert!(!pending_path(vault.path()).exists());
}

#[test]
fn a_timed_out_change_cannot_be_decided_and_writes_nothing() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = request("change", ORIGIN);
    let offer = match change_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no approval"),
    };
    state.expire_pending();
    assert_eq!(
        state.decide(
            offer.approval.approval_id(),
            ApprovalDecision::Selected("login-a".to_string())
        ),
        Err("approvalExpired")
    );
    assert!(state.pending_change_request().is_none());
    assert_eq!(live_password(&vault, "login-a"), OLD_PASSWORD);
}

#[test]
fn a_disconnected_or_stale_change_writes_nothing() {
    for case in ["disconnected", "stale", "locked"] {
        let vault = TestVault::with_login("login-a", ORIGIN);
        let (state, clock) = state_with_clock();
        let effects = FakeEffects::new(vault.path().to_path_buf());
        let request = request("change", ORIGIN);
        let offer = match change_response_in_state(&vault.state, &state, &effects, &request) {
            BrowserReply::Approval(offer) => offer,
            BrowserReply::Response(_) => panic!("no approval"),
        };
        let_delay_pass(&state, &clock);
        state
            .decide(
                offer.approval.approval_id(),
                ApprovalDecision::Selected("login-a".to_string()),
            )
            .expect("approved");
        let decision = offer.receiver.recv().expect("decision");
        let connected = case != "disconnected";
        if case == "stale" {
            vault.state.advance_session_epoch();
        }
        let kept_session = if case == "locked" {
            vault.state.session.lock().expect("session lock").take()
        } else {
            None
        };

        let response = complete_change_in_state(
            &vault.state,
            &effects,
            &request,
            &offer.approval,
            decision,
            &|| connected,
        );

        assert_eq!(response.message_type, "change-unavailable", "{case}");
        assert!(response.new_password.is_none(), "{case}");
        assert!(!wire(&response).contains(OLD_PASSWORD), "{case}");
        if let Some(session) = kept_session {
            *vault.state.session.lock().expect("session lock") = Some(session);
        }
        assert_eq!(live_password(&vault, "login-a"), OLD_PASSWORD, "{case}");
        assert!(!pending_path(vault.path()).exists(), "{case}");
        if case != "disconnected" {
            assert!(effects
                .calls()
                .contains(&Effect::EmitBrowserApprovalCancelled {
                    kind: ApprovalKind::Change,
                    approval_id: offer.approval.approval_id().to_string(),
                    reason: "vaultChanged",
                }));
        }
    }
}

#[test]
fn a_lookalike_page_gets_no_change_approval() {
    let vault = TestVault::with_login("login-a", "https://apple.com");
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = request("change", "https://app1e.com");
    let BrowserReply::Response(response) =
        change_response_in_state(&vault.state, &state, &effects, &request)
    else {
        panic!("a lookalike page was offered a change");
    };
    assert_eq!(response.message_type, "change-unavailable");
    assert_eq!(response.reason.as_deref(), Some("lookalike"));
    assert_eq!(response.lookalike.as_deref(), Some("apple.com"));
    assert!(response.validate_for(&request));
    assert!(state.pending_change_request().is_none());
}

#[test]
fn a_change_for_a_site_with_no_login_or_a_locked_vault_is_refused() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let other = request("change", "https://other.example.org");
    let BrowserReply::Response(response) =
        change_response_in_state(&vault.state, &state, &effects, &other)
    else {
        panic!("offered");
    };
    assert_eq!(response.reason.as_deref(), Some("noMatch"));

    let session = vault.state.session.lock().expect("lock").take();
    let BrowserReply::Response(response) =
        change_response_in_state(&vault.state, &state, &effects, &request("change", ORIGIN))
    else {
        panic!("offered while locked");
    };
    assert_eq!(response.reason.as_deref(), Some("locked"));
    *vault.state.session.lock().expect("lock") = session;
}

#[test]
fn a_login_set_to_never_fill_is_not_offered_for_a_change() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    vault.seed(|payload| payload.entries[0].match_rule = MatchRule::Never);
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let BrowserReply::Response(response) =
        change_response_in_state(&vault.state, &state, &effects, &request("change", ORIGIN))
    else {
        panic!("offered");
    };
    assert_eq!(response.reason.as_deref(), Some("noMatch"));
}

#[test]
fn an_approved_create_saves_a_new_login_for_the_page() {
    let vault = TestVault::with_login("login-a", ORIGIN);

    let response = approved_create(&vault, "https://signup.example.net");

    assert_eq!(response.message_type, "created");
    let password = response.password.clone().expect("password");
    assert!(response.validate_for(&request("create", "https://signup.example.net")));
    let session = vault.state.session.lock().expect("session lock");
    let payload = session
        .as_ref()
        .expect("session")
        .open_payload()
        .expect("payload");
    let created: Vec<&VaultEntry> = payload
        .entries
        .iter()
        .filter(|entry| entry.url == "https://signup.example.net")
        .collect();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].password, password);
    assert_eq!(created[0].title, "signup.example.net");
    assert!(created[0].username.is_empty());
    drop(payload);
    drop(session);

    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert_eq!(list.changes.len(), 1);
    assert_eq!(list.changes[0].kind, PendingKind::New);
    assert!(!list.changes[0].can_go_back);
}

#[test]
fn a_create_on_a_never_save_site_is_refused_before_and_after_approval() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    vault.seed(|payload| {
        payload
            .never_save_sites
            .push("https://blocked.example.net".to_string())
    });
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let BrowserReply::Response(response) = create_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request("create", "https://blocked.example.net"),
    ) else {
        panic!("offered on a never save site");
    };
    assert_eq!(response.reason.as_deref(), Some("approvalDeclined"));

    let (state, clock) = state_with_clock();
    let request = request("create", "https://later.example.net");
    let offer = match create_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no approval"),
    };
    let_delay_pass(&state, &clock);
    state
        .decide(offer.approval.approval_id(), ApprovalDecision::Approved)
        .expect("approved");
    let decision = offer.receiver.recv().expect("decision");
    {
        let mut session = vault.state.session.lock().expect("lock");
        let session = session.as_mut().expect("session");
        let mut payload = session.open_payload().expect("payload").clone();
        payload
            .never_save_sites
            .push("https://later.example.net".to_string());
        crate::vault::storage::commit_payload_change(session, payload).expect("committed");
    }
    let response = complete_create_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    );
    assert_eq!(response.reason.as_deref(), Some("approvalDeclined"));
    assert!(response.password.is_none());
}

#[test]
fn a_denied_or_disconnected_create_writes_nothing() {
    for case in ["denied", "disconnected"] {
        let vault = TestVault::with_login("login-a", ORIGIN);
        let (state, clock) = state_with_clock();
        let effects = FakeEffects::new(vault.path().to_path_buf());
        let request = request("create", "https://signup.example.net");
        let offer = match create_response_in_state(&vault.state, &state, &effects, &request) {
            BrowserReply::Approval(offer) => offer,
            BrowserReply::Response(_) => panic!("no approval"),
        };
        let_delay_pass(&state, &clock);
        let decision = if case == "denied" {
            ApprovalDecision::Denied
        } else {
            ApprovalDecision::Approved
        };
        state
            .decide(offer.approval.approval_id(), decision)
            .expect("decided");
        let decision = offer.receiver.recv().expect("decision");
        let response = complete_create_in_state(
            &vault.state,
            &effects,
            &request,
            &offer.approval,
            decision,
            &|| case != "disconnected",
        );
        assert_eq!(response.message_type, "create-unavailable");
        assert!(response.password.is_none());
        let session = vault.state.session.lock().expect("lock");
        let payload = session
            .as_ref()
            .expect("session")
            .open_payload()
            .expect("payload");
        assert_eq!(payload.entries.len(), 1, "{case}");
        drop(payload);
        drop(session);
        assert!(!pending_path(vault.path()).exists());
    }
}

#[test]
fn an_approval_too_soon_after_the_window_appears_is_refused() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let (state, _clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = request("create", "https://signup.example.net");
    let offer = match create_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no approval"),
    };
    assert!(state
        .decide(offer.approval.approval_id(), ApprovalDecision::Approved)
        .is_err());
}

#[test]
fn a_foreign_or_misplaced_handle_does_nothing() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let response = approved_change(&vault);
    let handle = response.handle.clone().expect("handle");
    let foreign = "A".repeat(43);

    let unknown = report(&vault, &foreign, "accepted");
    assert_eq!(unknown.state.as_deref(), Some("unknown"));
    let other_origin = pending_response_in_state(
        &vault.state,
        &pending(&handle, "accepted", "https://other.example.com"),
    );
    assert_eq!(other_origin.state.as_deref(), Some("unknown"));

    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert_eq!(list.changes.len(), 1);
    assert!(!list.changes[0].accepted);
}

#[test]
fn a_not_filled_report_records_the_fill_and_never_changes_the_live_password() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let response = approved_change(&vault);
    let handle = response.handle.clone().expect("handle");
    let new_password = response.new_password.clone().expect("new password");

    let reported = report(&vault, &handle, "notFilled");

    assert_eq!(reported.state.as_deref(), Some("unconfirmed"));
    assert_eq!(live_password(&vault, "login-a"), new_password);
    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert_eq!(list.changes[0].fill, FillState::NotFilled);
    assert!(list.changes[0].can_go_back);
}

#[test]
fn a_fill_report_is_kept_once() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let handle = approved_change(&vault).handle.clone().expect("handle");
    report(&vault, &handle, "filled");
    report(&vault, &handle, "notFilled");
    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert_eq!(list.changes[0].fill, FillState::Filled);
}

#[test]
fn an_accepted_change_is_confirmed_once_and_a_replay_changes_nothing() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let response = approved_change(&vault);
    let handle = response.handle.clone().expect("handle");
    let new_password = response.new_password.clone().expect("new password");
    let epoch = vault.state.session_epoch();

    let first = report(&vault, &handle, "accepted");
    let replay = report(&vault, &handle, "accepted");
    let late = report(&vault, &handle, "notFilled");

    assert_eq!(first.state.as_deref(), Some("confirmed"));
    assert_eq!(replay.state.as_deref(), Some("confirmed"));
    assert_eq!(late.state.as_deref(), Some("confirmed"));
    assert_eq!(live_password(&vault, "login-a"), new_password);
    assert_eq!(vault.state.session_epoch(), epoch);
    assert!(list_pending_changes_in_state(&vault.state)
        .expect("list")
        .changes
        .is_empty());
}

#[test]
fn an_expired_handle_is_unknown_but_the_notice_stays() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let handle = approved_change(&vault).handle.clone().expect("handle");
    rewrite_created_at(&vault, HANDLE_LIFETIME_SECS + 1);

    let reported = report(&vault, &handle, "accepted");

    assert_eq!(reported.state.as_deref(), Some("unknown"));
    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert_eq!(list.changes.len(), 1);
    assert!(!list.changes[0].accepted);
}

#[test]
fn the_notice_escalates_from_day_23_and_stops_offering_go_back_once_history_drops_it() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    approved_change(&vault);
    rewrite_created_at(&vault, 23 * 86_400);
    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert!(list.changes[0].urgent);
    assert_eq!(list.changes[0].days_left, Some(7));

    vault.seed(|payload| {
        for entry in &mut payload.history {
            entry.captured_at = unix_timestamp() - HISTORY_RETENTION_SECONDS - 1;
        }
    });
    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert_eq!(list.changes.len(), 1);
    assert!(!list.changes[0].can_go_back);
    assert!(!list.changes[0].urgent);
    assert_eq!(list.changes[0].days_left, None);
}

#[test]
fn a_locked_vault_answers_reports_with_locked_and_a_restart_keeps_the_change() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let response = approved_change(&vault);
    let handle = response.handle.clone().expect("handle");
    let new_password = response.new_password.clone().expect("new password");

    let session = vault.state.session.lock().expect("lock").take();
    let locked = report(&vault, &handle, "accepted");
    assert_eq!(locked.message_type, "pending-unavailable");
    assert_eq!(locked.reason.as_deref(), Some("locked"));
    drop(session);

    vault.reopen();

    assert_eq!(live_password(&vault, "login-a"), new_password);
    assert_eq!(
        list_pending_changes_in_state(&vault.state)
            .expect("list")
            .changes
            .len(),
        1
    );
    let accepted = report(&vault, &handle, "accepted");
    assert_eq!(accepted.state.as_deref(), Some("confirmed"));
}

#[test]
fn going_back_restores_the_old_password_and_keeps_the_new_one_in_history() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let response = approved_change(&vault);
    let handle = response.handle.clone().expect("handle");
    let new_password = response.new_password.clone().expect("new password");
    let id = list_pending_changes_in_state(&vault.state)
        .expect("list")
        .changes[0]
        .id
        .clone();

    let list = go_back_pending_change_in_state(&vault.state, &id).expect("went back");

    assert!(list.changes.is_empty());
    assert_eq!(live_password(&vault, "login-a"), OLD_PASSWORD);
    assert!(history_passwords(&vault, "login-a").contains(&new_password));
    assert_eq!(
        report(&vault, &handle, "accepted").state.as_deref(),
        Some("returned")
    );
    assert!(go_back_pending_change_in_state(&vault.state, &id).is_err());
}

#[test]
fn going_back_is_refused_after_the_login_was_edited() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let response = approved_change(&vault);
    let new_password = response.new_password.clone().expect("new password");
    vault.seed(|payload| {
        payload.entries[0].password = "fictional-typed-later".to_string();
        payload.entries[0].revision += 1;
    });
    let id = list_pending_changes_in_state(&vault.state)
        .expect("list")
        .changes[0]
        .id
        .clone();

    assert!(go_back_pending_change_in_state(&vault.state, &id).is_err());
    assert_eq!(live_password(&vault, "login-a"), "fictional-typed-later");
    assert!(history_passwords(&vault, "login-a").contains(&OLD_PASSWORD.to_string()));
    let _ = new_password;
}

#[test]
fn a_typed_password_after_a_change_is_called_a_newer_password() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    approved_change(&vault);
    {
        let mut session = vault.state.session.lock().expect("lock");
        let session = session.as_mut().expect("session");
        let payload = session.open_payload().expect("payload");
        let entry = payload.entries[0].clone();
        let next = crate::vault::storage::payload_with_saved_login(
            &payload,
            entry,
            Some("fictional-typed-later".to_string()),
            100,
        )
        .expect("typed");
        drop(payload);
        crate::vault::storage::commit_payload_change(session, next).expect("committed");
    }

    let list = list_pending_changes_in_state(&vault.state).expect("list");

    assert!(!list.changes[0].can_go_back);
    assert!(list.changes[0].superseded);
}

fn second_change(vault: &TestVault) -> BrowserResponse {
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let offer = match change_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request("change", ORIGIN),
    ) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no approval"),
    };
    let ApprovalEvent::Change(event) = offer.approval.event() else {
        panic!("not a change");
    };
    assert_eq!(event.unconfirmed, vec!["login-a".to_string()]);
    let_delay_pass(&state, &clock);
    state
        .decide(
            offer.approval.approval_id(),
            ApprovalDecision::Selected("login-a".to_string()),
        )
        .expect("approved");
    let decision = offer.receiver.recv().expect("decision");
    complete_change_in_state(
        &vault.state,
        &effects,
        &request("change", ORIGIN),
        &offer.approval,
        decision,
        &|| true,
    )
}

#[test]
fn two_changes_for_one_login_keep_both_earlier_passwords_reachable() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let first = approved_change(&vault).new_password.clone().expect("first");
    let second = second_change(&vault);
    assert_eq!(second.current_password.as_deref(), Some(first.as_str()));
    let second = second.new_password.clone().expect("second");

    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert_eq!(list.changes.len(), 2);
    let newer = list.changes.first().expect("newer").clone();
    let older = list.changes.last().expect("older").clone();
    assert!(newer.can_go_back);
    assert!(!newer.superseded);
    assert!(!older.can_go_back);
    assert!(older.superseded);

    assert!(go_back_pending_change_in_state(&vault.state, &older.id).is_err());
    assert_eq!(live_password(&vault, "login-a"), second);

    go_back_pending_change_in_state(&vault.state, &newer.id).expect("went back");

    assert_eq!(live_password(&vault, "login-a"), first);
    let remaining = list_pending_changes_in_state(&vault.state)
        .expect("list")
        .changes;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, older.id);
    assert!(!remaining[0].can_go_back);
    let history = history_passwords(&vault, "login-a");
    assert!(history.contains(&OLD_PASSWORD.to_string()));
    assert!(history.contains(&first));
    assert!(history.contains(&second));
}

#[test]
fn an_older_change_cannot_undo_a_newer_change_the_site_accepted() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    approved_change(&vault);
    let accepted = second_change(&vault);
    let handle = accepted.handle.clone().expect("handle");
    let accepted_password = accepted.new_password.clone().expect("second");
    assert_eq!(
        report(&vault, &handle, "accepted").state.as_deref(),
        Some("confirmed")
    );
    let older = list_pending_changes_in_state(&vault.state)
        .expect("list")
        .changes;
    assert_eq!(older.len(), 1);
    assert!(older[0].superseded);
    assert!(!older[0].can_go_back);

    assert!(go_back_pending_change_in_state(&vault.state, &older[0].id).is_err());

    assert_eq!(live_password(&vault, "login-a"), accepted_password);
    assert_eq!(
        report(&vault, &handle, "accepted").state.as_deref(),
        Some("confirmed")
    );
}

#[test]
fn an_edit_that_keeps_the_password_is_not_called_a_newer_password() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    approved_change(&vault);
    {
        let mut session = vault.state.session.lock().expect("lock");
        let session = session.as_mut().expect("session");
        let payload = session.open_payload().expect("payload");
        let mut entry = payload.entries[0].clone();
        entry.title = "Renamed".to_string();
        let next = crate::vault::storage::payload_with_saved_login(&payload, entry, None, 100)
            .expect("renamed");
        drop(payload);
        crate::vault::storage::commit_payload_change(session, next).expect("committed");
    }

    let list = list_pending_changes_in_state(&vault.state).expect("list");

    assert!(!list.changes[0].can_go_back);
    assert!(!list.changes[0].superseded);
}

#[test]
fn keep_resolves_the_change_and_leaves_the_password() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let new_password = approved_change(&vault).new_password.clone().expect("new");
    let id = list_pending_changes_in_state(&vault.state)
        .expect("list")
        .changes[0]
        .id
        .clone();
    let list = keep_pending_change_in_state(&vault.state, &id).expect("kept");
    assert!(list.changes.is_empty());
    assert_eq!(live_password(&vault, "login-a"), new_password);
    assert!(keep_pending_change_in_state(&vault.state, &id).is_err());
}

#[test]
fn an_accepted_sign_up_attaches_the_username_once_and_only_to_an_untouched_login() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let response = approved_create(&vault, ORIGIN);
    let handle = response.handle.clone().expect("handle");
    let password = response.password.clone().expect("password");
    let mut accept = pending(&handle, "accepted", ORIGIN);
    accept.username = Some("  alice@example.com  ".to_string());

    let reported = pending_response_in_state(&vault.state, &accept);

    assert_eq!(reported.state.as_deref(), Some("confirmed"));
    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert_eq!(list.changes.len(), 1);
    assert_eq!(list.changes[0].username, "alice@example.com");
    assert!(list.changes[0].accepted);
    let item_id = list.changes[0].item_id.clone();
    assert_eq!(live_password(&vault, &item_id), password);

    let mut again = pending(&handle, "accepted", ORIGIN);
    again.username = Some("mallory@example.com".to_string());
    pending_response_in_state(&vault.state, &again);
    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert_eq!(list.changes[0].username, "alice@example.com");
}

#[test]
fn a_username_is_not_attached_to_an_edited_login_or_to_a_change() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let response = approved_create(&vault, "https://signup.example.net");
    let handle = response.handle.clone().expect("handle");
    vault.seed(|payload| {
        let entry = payload
            .entries
            .iter_mut()
            .find(|entry| entry.url == "https://signup.example.net")
            .expect("created");
        entry.title = "Renamed".to_string();
        entry.revision += 1;
    });
    let mut accept = pending(&handle, "accepted", "https://signup.example.net");
    accept.username = Some("alice@example.com".to_string());
    pending_response_in_state(&vault.state, &accept);
    let list = list_pending_changes_in_state(&vault.state).expect("list");
    assert!(list.changes[0].username.is_empty());

    let change = approved_change(&vault);
    let mut accept = pending(&change.handle.clone().expect("handle"), "accepted", ORIGIN);
    accept.username = Some("alice@example.com".to_string());
    pending_response_in_state(&vault.state, &accept);
    let session = vault.state.session.lock().expect("lock");
    let payload = session
        .as_ref()
        .expect("session")
        .open_payload()
        .expect("payload");
    assert_eq!(
        payload
            .entries
            .iter()
            .find(|entry| entry.id == "login-a")
            .expect("login")
            .username,
        "fictional-user"
    );
}

#[test]
fn discarding_a_new_login_moves_it_to_trash() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    approved_create(&vault, "https://signup.example.net");
    let view = list_pending_changes_in_state(&vault.state)
        .expect("list")
        .changes[0]
        .clone();

    let list = discard_pending_login_in_state(&vault.state, &view.id).expect("discarded");

    assert!(list.changes.is_empty());
    let session = vault.state.session.lock().expect("lock");
    let payload = session
        .as_ref()
        .expect("session")
        .open_payload()
        .expect("payload");
    assert!(payload.entries.iter().all(|entry| entry.id != view.item_id));
    assert!(payload
        .trash
        .iter()
        .any(|item| item.item.id() == view.item_id));
}

#[test]
fn a_damaged_list_is_set_aside_and_the_passwords_stay_in_the_vault() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let new_password = approved_change(&vault).new_password.clone().expect("new");
    std::fs::write(pending_path(vault.path()), b"{\"format\":\"damaged\"}").expect("damaged");

    let list = list_pending_changes_in_state(&vault.state).expect("list");

    assert!(list.changes.is_empty());
    assert_eq!(live_password(&vault, "login-a"), new_password);
    assert!(history_passwords(&vault, "login-a").contains(&OLD_PASSWORD.to_string()));
    assert!(crate::vault::pending_change::damaged_pending_path(vault.path()).exists());
}

fn notice_count(vault: &TestVault) -> usize {
    list_pending_changes_in_state(&vault.state)
        .expect("list")
        .changes
        .len()
}

#[test]
fn a_master_password_change_keeps_every_notice() {
    use crate::vault::ChangeMasterPasswordRequest;
    let vault = TestVault::with_login("login-a", ORIGIN);
    approved_change(&vault);
    approved_create(&vault, "https://signup.example.net");
    assert_eq!(notice_count(&vault), 2);
    {
        let mut session = vault.state.session.lock().expect("session lock");
        let session = session.as_mut().expect("session");
        session.recovery_wrap = None;
        session.recovery_kdf = None;
        crate::vault::storage::persist_session(session).expect("persisted");
    }
    let effects = FakeEffects::new(vault.path().to_path_buf());

    super::unlock::change_master_password_in_state(
        &vault.state,
        &effects,
        ChangeMasterPasswordRequest {
            current_password: Some("fictional master password".to_string()),
            recovery_kit: None,
            new_password: "fictional new master password".to_string(),
        },
    )
    .expect("changed");

    assert_eq!(notice_count(&vault), 2);
    assert!(!crate::vault::pending_change::damaged_pending_path(vault.path()).exists());
}

#[test]
fn adopting_a_new_vault_key_keeps_every_notice() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    approved_change(&vault);
    assert_eq!(notice_count(&vault), 1);
    {
        let mut session = vault.state.session.lock().expect("lock");
        let session = session.as_mut().expect("session");
        let payload = session.open_payload().expect("payload").clone();
        super::sync_adopt::adopt(session, [5_u8; 32], payload, "fictional master password")
            .expect("adopted");
    }

    assert_eq!(notice_count(&vault), 1);
}

#[test]
fn a_second_damaged_list_never_replaces_the_first() {
    use crate::vault::pending_change::damaged_pending_paths;
    let vault = TestVault::with_login("login-a", ORIGIN);
    let slots = damaged_pending_paths(vault.path());
    for round in 0..(slots.len() + 1) {
        std::fs::write(
            pending_path(vault.path()),
            format!("{{\"format\":\"damaged-{round}\"}}"),
        )
        .expect("damaged");
        list_pending_changes_in_state(&vault.state).expect("list");
    }

    for (round, slot) in slots.iter().enumerate() {
        assert_eq!(
            std::fs::read_to_string(slot).expect("kept copy"),
            format!("{{\"format\":\"damaged-{round}\"}}")
        );
    }
}

#[test]
fn a_list_that_cannot_be_read_now_is_left_in_place_and_refuses_changes() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    std::fs::create_dir(pending_path(vault.path())).expect("unreadable list");

    assert!(list_pending_changes_in_state(&vault.state).is_err());
    let response = approved_change(&vault);

    assert_eq!(response.message_type, "change-unavailable");
    assert_eq!(response.reason.as_deref(), Some("approvalUnavailable"));
    assert_eq!(live_password(&vault, "login-a"), OLD_PASSWORD);
    assert!(pending_path(vault.path()).is_dir());
    assert!(!crate::vault::pending_change::damaged_pending_path(vault.path()).exists());
}

#[cfg(unix)]
fn read_only_folder(vault: &TestVault, read_only: bool) {
    use std::os::unix::fs::PermissionsExt;
    let folder = vault.path().parent().expect("folder");
    let mode = if read_only { 0o500 } else { 0o700 };
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(mode)).expect("mode");
}

#[cfg(unix)]
#[test]
fn a_change_or_create_whose_list_cannot_be_written_never_touches_the_vault() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let before = std::fs::read(vault.path()).expect("vault bytes");
    read_only_folder(&vault, true);

    let changed = approved_change(&vault);
    let created = approved_create(&vault, "https://signup.example.net");

    read_only_folder(&vault, false);
    assert_eq!(changed.message_type, "change-unavailable");
    assert_eq!(changed.reason.as_deref(), Some("approvalUnavailable"));
    assert!(changed.new_password.is_none());
    assert_eq!(created.message_type, "create-unavailable");
    assert!(created.password.is_none());
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert_eq!(live_password(&vault, "login-a"), OLD_PASSWORD);
    assert_eq!(notice_count(&vault), 0);
}

#[cfg(unix)]
#[test]
fn a_report_whose_list_cannot_be_written_is_not_answered_as_success() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let handle = approved_change(&vault).handle.clone().expect("handle");
    read_only_folder(&vault, true);

    let reported = report(&vault, &handle, "accepted");

    read_only_folder(&vault, false);
    assert_eq!(reported.message_type, "pending-unavailable");
    assert_eq!(reported.reason.as_deref(), Some("approvalUnavailable"));
    assert!(reported.state.is_none());
    assert_eq!(notice_count(&vault), 1);
}

#[test]
fn a_change_that_was_never_committed_is_dropped_and_one_that_was_is_kept() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    approved_change(&vault);
    {
        let session = vault.state.session.lock().expect("session lock");
        let session = session.as_ref().expect("session");
        let mut changes = read_pending(session).expect("pending list");
        let committed = changes[0].clone();
        changes[0].applied = false;
        let mut abandoned = committed.clone();
        abandoned.id = "abandoned".to_string();
        abandoned.history_id = Some("history-never-written".to_string());
        abandoned.applied = false;
        changes.push(abandoned);
        let mut abandoned_new = committed;
        abandoned_new.id = "abandoned-new".to_string();
        abandoned_new.kind = PendingKind::New;
        abandoned_new.item_id = "login-never-written".to_string();
        abandoned_new.history_id = None;
        abandoned_new.applied = false;
        changes.push(abandoned_new);
        write_pending(session, &changes).expect("written");
    }

    let list = list_pending_changes_in_state(&vault.state).expect("list");

    assert_eq!(list.changes.len(), 1);
    assert_ne!(list.changes[0].id, "abandoned");
    let session = vault.state.session.lock().expect("session lock");
    let stored = read_pending(session.as_ref().expect("session")).expect("pending list");
    assert_eq!(stored.len(), 1);
    assert!(stored[0].applied);
}

#[test]
fn a_change_on_a_never_save_site_is_refused_before_and_after_approval() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = request("change", ORIGIN);
    let offer = match change_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no approval"),
    };
    let_delay_pass(&state, &clock);
    state
        .decide(
            offer.approval.approval_id(),
            ApprovalDecision::Selected("login-a".to_string()),
        )
        .expect("approved");
    let decision = offer.receiver.recv().expect("decision");
    vault.seed(|payload| payload.never_save_sites.push(ORIGIN.to_string()));

    let response = complete_change_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    );

    assert_eq!(response.message_type, "change-unavailable");
    assert_eq!(response.reason.as_deref(), Some("approvalDeclined"));
    assert!(response.new_password.is_none());
    assert_eq!(live_password(&vault, "login-a"), OLD_PASSWORD);

    let BrowserReply::Response(response) = change_response_in_state(
        &vault.state,
        &BrowserFillState::default(),
        &effects,
        &request,
    ) else {
        panic!("offered a change on a never save site");
    };
    assert_eq!(response.reason.as_deref(), Some("approvalDeclined"));
}

#[test]
fn a_username_with_control_or_direction_characters_is_not_attached() {
    for username in [
        "alice\u{202E}moc.elpmaxe@",
        "alice\u{2066}@example.com",
        "alice\u{200B}@example.com",
        "alice\u{0007}@example.com",
        "alice\n@example.com",
        "alice\u{FEFF}@example.com",
    ] {
        let vault = TestVault::with_login("login-a", ORIGIN);
        let response = approved_create(&vault, "https://signup.example.net");
        let handle = response.handle.clone().expect("handle");
        let mut accept = pending(&handle, "accepted", "https://signup.example.net");
        accept.username = Some(username.to_string());

        let reported = pending_response_in_state(&vault.state, &accept);

        assert_eq!(reported.state.as_deref(), Some("confirmed"), "{username:?}");
        let list = list_pending_changes_in_state(&vault.state).expect("list");
        assert!(list.changes[0].username.is_empty(), "{username:?}");
    }
}

fn without_recovery_wrap(vault: &TestVault) {
    let mut session = vault.state.session.lock().expect("session lock");
    let session = session.as_mut().expect("session");
    session.recovery_wrap = None;
    session.recovery_kdf = None;
    crate::vault::storage::persist_session(session).expect("persisted");
}

fn change_master_password(vault: &TestVault) -> crate::vault::VaultResult<()> {
    let effects = FakeEffects::new(vault.path().to_path_buf());
    super::unlock::change_master_password_in_state(
        &vault.state,
        &effects,
        crate::vault::ChangeMasterPasswordRequest {
            current_password: Some("fictional master password".to_string()),
            recovery_kit: None,
            new_password: "fictional new master password".to_string(),
        },
    )
    .map(|_| ())
}

#[test]
fn a_key_change_is_refused_while_the_list_cannot_be_read() {
    let vault = TestVault::with_login("login-a", ORIGIN);
    without_recovery_wrap(&vault);
    let before = std::fs::read(vault.path()).expect("vault bytes");
    std::fs::create_dir(pending_path(vault.path())).expect("unreadable list");

    assert!(change_master_password(&vault).is_err());

    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert!(pending_path(vault.path()).is_dir());
}

#[test]
fn a_key_change_interrupted_after_the_vault_commit_keeps_every_notice() {
    use crate::vault::pending_change::next_key_pending_path;
    let vault = TestVault::with_login("login-a", ORIGIN);
    approved_change(&vault);
    without_recovery_wrap(&vault);
    let old_key_list = std::fs::read(pending_path(vault.path())).expect("old list");

    change_master_password(&vault).expect("changed");
    let new_key_list = std::fs::read(pending_path(vault.path())).expect("new list");
    std::fs::write(next_key_pending_path(vault.path()), new_key_list).expect("staged list");
    std::fs::write(pending_path(vault.path()), old_key_list).expect("old list in place");

    assert_eq!(notice_count(&vault), 1);
    assert!(!next_key_pending_path(vault.path()).exists());
    assert!(!crate::vault::pending_change::damaged_pending_path(vault.path()).exists());
}

#[test]
fn a_list_staged_for_a_key_that_was_never_committed_is_removed() {
    use crate::vault::pending_change::next_key_pending_path;
    let vault = TestVault::with_login("login-a", ORIGIN);
    approved_change(&vault);
    let unused_key_list =
        crate::vault::pending_change::seal(&[9_u8; 32], "fictional-vault", &[]).expect("sealed");
    std::fs::write(next_key_pending_path(vault.path()), unused_key_list).expect("staged list");

    assert_eq!(notice_count(&vault), 1);
    assert!(!next_key_pending_path(vault.path()).exists());
}
