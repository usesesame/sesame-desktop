use std::sync::Arc;
use std::thread;

use zeroize::Zeroizing;

use crate::application::broker_tests::{let_delay_pass, state_with_clock};
use crate::application::tests::{Effect, FakeEffects};
use crate::browser_protocol::{
    BrowserRequest, CARD_PROTOCOL_VERSION, LOOKALIKE_PROTOCOL_VERSION, PROTOCOL_VERSION,
    TOTP_PROTOCOL_VERSION,
};
use crate::release::ReleasePresence;
use crate::test_support::{grant, TestVault};
use crate::vault::release_record::{EntryKind, FieldKind, MatchKind, Outcome, ReleaseDraft};
use crate::vault::{Card, CustomFieldEntry, Identity, VaultEntry, VaultState};

use super::backups::create_backup_in_state;
use super::browser_fill::{
    never_save_browser_site_in_state, resolve_browser_save_in_state, ApprovalDecision,
    ApprovalKind, NormalizedOrigin,
};
use super::browser_fill_broker::BrowserFillState;
use super::browser_replies::{
    card_response_in_state, complete_card_in_state, complete_fill_in_state,
    complete_identity_in_state, complete_save_in_state, complete_totp_in_state,
    fill_response_in_state, identity_response_in_state, record_decision, save_response_in_state,
    totp_response_in_state, BrowserApprovalOffer, BrowserReply,
};
use super::lifecycle::unlock_vault_in_state;
use super::logins::reveal_login_secret_in_state;
use super::quick_access::quick_access_field_in_state;
use super::release_record::{
    clear_release_record_in_state, record, release_record_hint_in_state,
    release_record_page_in_state, set_release_record_retention_in_state, ReleaseEntryView,
    ReleaseRecordQuery,
};
use super::reveal::{copy_item_field_in_state, item_field_in_state, reveal_item_field_in_state};

const CANARY: &str = "fictional-record-canary";
const PASSWORD: &str = "fictional master password";
const RFC_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn request(message_type: &str, version: u8, origin: &str, id: &str) -> BrowserRequest {
    BrowserRequest {
        version,
        message_type: message_type.to_string(),
        request_id: id.to_string(),
        origin: Some(origin.to_string()),
        fields: None,
        username: None,
        password: None,
        title: None,
        kind: None,
        style: None,
        size: None,
        handle: None,
        action: None,
    }
}

fn fill_request(origin: &str) -> BrowserRequest {
    request("fill", LOOKALIKE_PROTOCOL_VERSION, origin, "fill-1")
}

fn entries(vault: &VaultState) -> Vec<ReleaseEntryView> {
    release_record_page_in_state(
        vault,
        ReleaseRecordQuery {
            limit: Some(1_000),
            ..ReleaseRecordQuery::default()
        },
    )
    .expect("record page")
    .entries
}

fn only(vault: &VaultState) -> ReleaseEntryView {
    let mut found = entries(vault);
    assert_eq!(found.len(), 1, "{found:?}");
    found.remove(0)
}

fn offer(reply: BrowserReply) -> BrowserApprovalOffer {
    match reply {
        BrowserReply::Approval(offer) => *offer,
        BrowserReply::Response(response) => {
            panic!("no approval was offered: {:?}", response.reason)
        }
    }
}

fn canary_vault() -> TestVault {
    let vault = TestVault::with_login("login-a", "https://example.com");
    vault.seed(|payload| {
        payload.entries[0].password = format!("{CANARY}-password");
        payload.entries[0].username = "fictional-user".to_string();
        payload.entries[0].totp = Some(RFC_KEY.to_string());
        payload.entries[0].backup_codes = vec![format!("{CANARY}-code")];
        payload.entries[0].custom_fields = vec![CustomFieldEntry {
            label: "Answer".to_string(),
            value: format!("{CANARY}-answer"),
            kind: "secret".to_string(),
        }];
        let mut card = Card::default();
        card.id = "card-a".to_string();
        card.title = "Fictional card".to_string();
        card.number = format!("{CANARY}-4242");
        card.security_code = "123".to_string();
        card.cardholder_name = "Fictional Person".to_string();
        payload.cards.push(card);
        let mut identity = Identity::default();
        identity.id = "identity-a".to_string();
        identity.label = "Home".to_string();
        identity.full_name = format!("{CANARY}-name");
        identity.email = "person@example.com".to_string();
        payload.identities.push(identity);
    });
    vault
}

fn approve(state: &BrowserFillState, offer: &BrowserApprovalOffer, id: &str) -> ApprovalDecision {
    state
        .decide(
            offer.approval.approval_id(),
            ApprovalDecision::Selected(id.to_string()),
        )
        .expect("approved");
    offer.receiver.recv().expect("decision")
}

#[test]
fn an_approved_login_fill_is_recorded_with_item_host_fields_and_match() {
    let vault = canary_vault();
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request("https://example.com");
    let offer = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));
    let_delay_pass(&state, &clock);
    let decision = approve(&state, &offer, "login-a");

    let response = complete_fill_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    );

    assert!(response.password.is_some());
    let entry = only(&vault.state);
    assert_eq!(entry.kind, EntryKind::BrowserFill);
    assert_eq!(entry.outcome, Outcome::Released);
    assert_eq!(entry.item_id.as_deref(), Some("login-a"));
    assert_eq!(entry.item_kind.as_deref(), Some("login"));
    assert_eq!(entry.host.as_deref(), Some("example.com"));
    assert_eq!(entry.match_kind, Some(MatchKind::Exact));
    assert_eq!(entry.fields, vec![FieldKind::Username, FieldKind::Password]);
}

#[test]
fn every_refused_or_unanswered_browser_outcome_has_its_own_entry() {
    let cases: [(ApprovalDecision, Option<Outcome>, Outcome); 5] = [
        (ApprovalDecision::Denied, None, Outcome::Denied),
        (
            ApprovalDecision::Denied,
            Some(Outcome::Withdrawn),
            Outcome::Withdrawn,
        ),
        (
            ApprovalDecision::Denied,
            Some(Outcome::NeverSave),
            Outcome::NeverSave,
        ),
        (ApprovalDecision::InvalidSelection, None, Outcome::Mismatch),
        (ApprovalDecision::Saved, None, Outcome::Mismatch),
    ];
    for (decision, marked, expected) in cases {
        let vault = TestVault::with_login("login-a", "https://example.com");
        let state = BrowserFillState::default();
        if let Some(marked) = marked {
            state.mark_outcome("approval-1", marked);
        }
        let origin = NormalizedOrigin::from_request("https://example.com").expect("origin");

        record_decision(
            &vault.state,
            &state,
            "approval-1",
            ApprovalKind::Fill,
            &origin,
            &decision,
        );

        let entry = only(&vault.state);
        assert_eq!(entry.outcome, expected);
        assert_eq!(entry.host.as_deref(), Some("example.com"));
        assert!(entry.item_id.is_none());
    }
}

#[test]
fn a_selected_or_saved_decision_is_recorded_where_the_value_is_read() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    let state = BrowserFillState::default();
    let origin = NormalizedOrigin::from_request("https://example.com").expect("origin");
    record_decision(
        &vault.state,
        &state,
        "approval-1",
        ApprovalKind::Fill,
        &origin,
        &ApprovalDecision::Selected("login-a".to_string()),
    );
    record_decision(
        &vault.state,
        &state,
        "approval-1",
        ApprovalKind::Save,
        &origin,
        &ApprovalDecision::Saved,
    );
    assert!(entries(&vault.state).is_empty());
}

#[test]
fn cancelling_a_pending_approval_is_recorded_as_withdrawn() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    let (state, _) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request("https://example.com");
    let offer = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));

    state.cancel_pending();
    let decision = offer.receiver.recv().expect("decision");
    record_decision(
        &vault.state,
        &state,
        offer.approval.approval_id(),
        ApprovalKind::Fill,
        offer.approval.origin(),
        &decision,
    );

    assert_eq!(only(&vault.state).outcome, Outcome::Withdrawn);
}

#[test]
fn refusals_before_any_approval_are_recorded() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    vault.seed(|payload| {
        let mut entry = VaultEntry::default();
        entry.id = "login-b".to_string();
        entry.title = "Lookalike target".to_string();
        entry.url = "https://northwindtraders.example.com".to_string();
        entry.username = "fictional-user".to_string();
        entry.password = "fictional-other-secret".to_string();
        payload.entries.push(entry);
    });
    let (state, _) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());

    fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &fill_request("https://unknown.example.org"),
    );
    let first = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &fill_request("https://example.com"),
    ));
    fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request(
            "fill",
            LOOKALIKE_PROTOCOL_VERSION,
            "https://example.com",
            "fill-2",
        ),
    );
    fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request(
            "fill",
            LOOKALIKE_PROTOCOL_VERSION,
            "https://example.com",
            "fill-1",
        ),
    );
    drop(first);

    let outcomes: Vec<Outcome> = entries(&vault.state)
        .into_iter()
        .map(|entry| entry.outcome)
        .collect();
    assert!(outcomes.contains(&Outcome::NoMatch));
    assert!(outcomes.contains(&Outcome::Busy));
    assert!(outcomes.contains(&Outcome::Replayed));
}

#[test]
fn a_lookalike_refusal_names_the_saved_site_it_imitates() {
    let vault = TestVault::with_login("login-a", "https://northwindtraders.com");
    let (state, _) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());

    fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &fill_request("https://northwindtradres.com"),
    );

    let entry = only(&vault.state);
    assert_eq!(entry.outcome, Outcome::Lookalike);
    assert_eq!(entry.host.as_deref(), Some("northwindtradres.com"));
    assert_eq!(entry.similar_to.as_deref(), Some("northwindtraders.com"));
}

#[test]
fn a_lost_connection_or_a_vault_change_after_approval_is_recorded_with_the_item() {
    for case in ["connection", "vault"] {
        let vault = TestVault::with_login("login-a", "https://example.com");
        let (state, clock) = state_with_clock();
        let effects = FakeEffects::new(vault.path().to_path_buf());
        let request = fill_request("https://example.com");
        let offer = offer(fill_response_in_state(
            &vault.state,
            &state,
            &effects,
            &request,
        ));
        let_delay_pass(&state, &clock);
        let decision = approve(&state, &offer, "login-a");
        if case == "vault" {
            vault.state.advance_session_epoch();
        }

        let connected = case == "vault";
        let response = complete_fill_in_state(
            &vault.state,
            &effects,
            &request,
            &offer.approval,
            decision,
            &|| connected,
        );

        assert!(response.password.is_none());
        let entry = only(&vault.state);
        let expected = if case == "vault" {
            Outcome::VaultChanged
        } else {
            Outcome::ConnectionClosed
        };
        assert_eq!(entry.outcome, expected);
        assert_eq!(entry.item_id.as_deref(), Some("login-a"));
    }
}

#[test]
fn a_lock_between_the_decision_and_the_release_is_written_at_the_next_unlock() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request("https://example.com");
    let offer = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));
    let_delay_pass(&state, &clock);
    let decision = approve(&state, &offer, "login-a");
    vault.state.lock_for_lifecycle().expect("locked");

    let response = complete_fill_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    );
    assert!(response.password.is_none());
    fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &fill_request("https://example.com"),
    );

    unlock_vault_in_state(
        &vault.state,
        &ReleasePresence::default(),
        &effects,
        Zeroizing::new(PASSWORD.to_string()),
    )
    .expect("unlocked");

    let found = entries(&vault.state);
    let changed = found
        .iter()
        .find(|entry| entry.outcome == Outcome::VaultChanged)
        .expect("vault changed entry");
    assert!(changed.late);
    assert!(changed.item_id.is_none());
    assert!(found
        .iter()
        .any(|entry| entry.outcome == Outcome::Locked && entry.late));
}

#[test]
fn one_time_code_card_and_identity_fills_record_the_fields_they_sent() {
    let vault = canary_vault();
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());

    let totp = request(
        "totp",
        TOTP_PROTOCOL_VERSION,
        "https://example.com",
        "totp-1",
    );
    let offered = offer(totp_response_in_state(
        &vault.state,
        &state,
        &effects,
        &totp,
    ));
    let_delay_pass(&state, &clock);
    let decision = approve(&state, &offered, "login-a");
    complete_totp_in_state(
        &vault.state,
        &effects,
        &totp,
        &offered.approval,
        decision,
        &|| true,
    );

    let mut card = request(
        "card",
        CARD_PROTOCOL_VERSION,
        "https://shop.example.com",
        "card-1",
    );
    card.fields = Some("number,securityCode".to_string());
    let offered = offer(card_response_in_state(
        &vault.state,
        &state,
        &effects,
        &card,
    ));
    let_delay_pass(&state, &clock);
    let decision = approve(&state, &offered, "card-a");
    complete_card_in_state(
        &vault.state,
        &effects,
        &card,
        &offered.approval,
        decision,
        &|| true,
    );

    let mut identity = request(
        "identity",
        PROTOCOL_VERSION,
        "https://shop.example.com",
        "id-1",
    );
    identity.fields = Some("fullName,email".to_string());
    let offered = offer(identity_response_in_state(
        &vault.state,
        &state,
        &effects,
        &identity,
    ));
    let_delay_pass(&state, &clock);
    let decision = approve(&state, &offered, "identity-a");
    complete_identity_in_state(
        &vault.state,
        &effects,
        &identity,
        &offered.approval,
        decision,
        &|| true,
    );

    let found = entries(&vault.state);
    let by_kind = |kind: EntryKind| {
        found
            .iter()
            .find(|entry| entry.kind == kind && entry.outcome == Outcome::Released)
            .unwrap_or_else(|| panic!("missing {kind:?}"))
            .clone()
    };
    assert_eq!(
        by_kind(EntryKind::BrowserTotp).fields,
        vec![FieldKind::TwoFactorCode]
    );
    assert_eq!(
        by_kind(EntryKind::BrowserCard).fields,
        vec![FieldKind::CardNumber, FieldKind::SecurityCode]
    );
    assert_eq!(
        by_kind(EntryKind::BrowserIdentity).fields,
        vec![FieldKind::FullName, FieldKind::Email]
    );
    assert_eq!(
        by_kind(EntryKind::BrowserCard).host.as_deref(),
        Some("shop.example.com")
    );
}

fn save_request(kind: &str) -> BrowserRequest {
    let mut save = request("save", PROTOCOL_VERSION, "https://example.com", "save-1");
    save.username = Some("fictional-user".to_string());
    save.password = Some(format!("{CANARY}-saved"));
    save.title = Some("Northwind".to_string());
    save.kind = Some(kind.to_string());
    save
}

#[test]
fn an_approved_save_is_recorded_when_it_is_committed() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let mut save = save_request("update");
    let offered = offer(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut save,
    ));
    let_delay_pass(&state, &clock);

    resolve_browser_save_in_state(
        &state,
        &vault.state,
        &effects,
        offered.approval.approval_id(),
        true,
        Some("login-a".to_string()),
    )
    .expect("saved");
    let decision = offered.receiver.recv().expect("decision");
    record_decision(
        &vault.state,
        &state,
        offered.approval.approval_id(),
        ApprovalKind::Save,
        offered.approval.origin(),
        &decision,
    );
    complete_save_in_state(&save, decision);

    let entry = only(&vault.state);
    assert_eq!(entry.kind, EntryKind::BrowserSave);
    assert_eq!(entry.outcome, Outcome::Updated);
    assert_eq!(entry.item_id.as_deref(), Some("login-a"));
}

#[test]
fn choosing_never_save_is_recorded_once_as_never_save() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let mut save = save_request("new");
    let offered = offer(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut save,
    ));
    let_delay_pass(&state, &clock);

    never_save_browser_site_in_state(
        &state,
        &vault.state,
        &effects,
        offered.approval.approval_id(),
    )
    .expect("never save");
    let decision = offered.receiver.recv().expect("decision");
    record_decision(
        &vault.state,
        &state,
        offered.approval.approval_id(),
        ApprovalKind::Save,
        offered.approval.origin(),
        &decision,
    );

    assert_eq!(only(&vault.state).outcome, Outcome::NeverSave);
}

#[test]
fn reveals_copies_and_quick_access_are_recorded_after_presence() {
    let vault = canary_vault();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());

    assert!(
        reveal_item_field_in_state(&vault.state, &presence, "card-a", "card", "number").is_err()
    );
    assert!(entries(&vault.state).is_empty());

    grant(&vault, &presence);
    reveal_item_field_in_state(&vault.state, &presence, "card-a", "card", "number")
        .expect("revealed");
    copy_item_field_in_state(
        &vault.state,
        &presence,
        &effects,
        "login-a",
        "login",
        "field:0",
        None,
    )
    .expect("copied");
    reveal_login_secret_in_state(&vault.state, &presence, "login-a").expect("revealed");
    quick_access_field_in_state(&vault.state, &presence, "login-a", "password").expect("copied");

    let found = entries(&vault.state);
    let kinds: Vec<(EntryKind, Option<&str>, Vec<FieldKind>)> = found
        .iter()
        .rev()
        .map(|entry| (entry.kind, entry.item_id.as_deref(), entry.fields.clone()))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (
                EntryKind::Reveal,
                Some("card-a"),
                vec![FieldKind::CardNumber]
            ),
            (
                EntryKind::Copy,
                Some("login-a"),
                vec![FieldKind::CustomField]
            ),
            (
                EntryKind::Reveal,
                Some("login-a"),
                vec![FieldKind::Password]
            ),
            (
                EntryKind::QuickAccess,
                Some("login-a"),
                vec![FieldKind::Password]
            ),
        ]
    );
}

#[test]
fn reading_a_field_for_a_breach_check_records_nothing() {
    let vault = canary_vault();
    let presence = ReleasePresence::default();
    grant(&vault, &presence);

    item_field_in_state(&vault.state, &presence, "login-a", "login", "password").expect("read");

    assert!(entries(&vault.state).is_empty());
}

#[test]
fn a_local_backup_is_recorded() {
    let vault = TestVault::with_login("login-a", "https://example.com");

    create_backup_in_state(&vault.state).expect("backup");

    assert_eq!(only(&vault.state).kind, EntryKind::BackupCreated);
}

#[test]
fn recording_never_saves_the_vault_or_moves_the_snapshot() {
    let vault = canary_vault();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    grant(&vault, &presence);
    let bytes = std::fs::read(vault.path()).expect("vault bytes");
    let epoch = vault.state.session_epoch();
    let snapshot = vault
        .state
        .session
        .lock()
        .expect("session")
        .as_ref()
        .expect("unlocked")
        .snapshot();

    reveal_item_field_in_state(&vault.state, &presence, "card-a", "card", "number")
        .expect("revealed");
    copy_item_field_in_state(
        &vault.state,
        &presence,
        &effects,
        "login-a",
        "login",
        "password",
        None,
    )
    .expect("copied");
    record(
        &vault.state,
        ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Denied).host("example.com"),
    );

    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), bytes);
    assert_eq!(vault.state.session_epoch(), epoch);
    let after = vault
        .state
        .session
        .lock()
        .expect("session")
        .as_ref()
        .expect("unlocked")
        .snapshot();
    assert_eq!(after.revision, snapshot.revision);
    assert_eq!(after.entries.len(), snapshot.entries.len());
}

#[test]
fn a_lock_during_writes_loses_no_entry() {
    let vault = Arc::new(TestVault::with_login("login-a", "https://example.com"));
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let writers: Vec<_> = (0..4)
        .map(|writer| {
            let vault = Arc::clone(&vault);
            thread::spawn(move || {
                for index in 0..40 {
                    record(
                        &vault.state,
                        ReleaseDraft::new(EntryKind::Copy, Outcome::Released)
                            .item(&format!("w{writer}-{index}"), "login")
                            .host(&format!("w{writer}.example.com")),
                    );
                }
            })
        })
        .collect();
    thread::sleep(std::time::Duration::from_millis(5));
    vault.state.lock_for_lifecycle().expect("locked");
    for writer in writers {
        writer.join().expect("writer finished");
    }

    unlock_vault_in_state(
        &vault.state,
        &ReleasePresence::default(),
        &effects,
        Zeroizing::new(PASSWORD.to_string()),
    )
    .expect("unlocked");

    let page = release_record_page_in_state(
        &vault.state,
        ReleaseRecordQuery {
            limit: Some(1_000),
            ..ReleaseRecordQuery::default()
        },
    )
    .expect("page");
    let total: u32 = page.entries.iter().map(|entry| entry.count).sum();
    assert_eq!(total, 160);
    assert_eq!(page.status.notice, None);
    assert_eq!(page.status.unwritten, 0);
}

#[test]
fn a_flood_of_denied_requests_from_one_page_stays_small() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    let origin = NormalizedOrigin::from_request("https://flood.example.com").expect("origin");
    let state = BrowserFillState::default();
    for _ in 0..2_000 {
        record_decision(
            &vault.state,
            &state,
            "approval-1",
            ApprovalKind::Fill,
            &origin,
            &ApprovalDecision::Denied,
        );
    }
    vault.state.lock_for_lifecycle().expect("locked");
    let effects = FakeEffects::new(vault.path().to_path_buf());
    unlock_vault_in_state(
        &vault.state,
        &ReleasePresence::default(),
        &effects,
        Zeroizing::new(PASSWORD.to_string()),
    )
    .expect("unlocked");

    let found = entries(&vault.state);
    assert_eq!(found.len(), 2);
    assert_eq!(found.iter().map(|entry| entry.count).sum::<u32>(), 2_000);
}

#[test]
fn no_entry_record_file_page_or_diagnostic_holds_a_secret() {
    let vault = canary_vault();
    let presence = ReleasePresence::default();
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    grant(&vault, &presence);

    for (id, kind, field) in [
        ("login-a", "login", "password"),
        ("login-a", "login", "backupCodes"),
        ("login-a", "login", "field:0"),
        ("card-a", "card", "number"),
    ] {
        reveal_item_field_in_state(&vault.state, &presence, id, kind, field).expect("revealed");
        copy_item_field_in_state(&vault.state, &presence, &effects, id, kind, field, None)
            .expect("copied");
    }
    quick_access_field_in_state(&vault.state, &presence, "login-a", "password").expect("copied");
    quick_access_field_in_state(&vault.state, &presence, "identity-a", "fullName").expect("copied");
    let request = fill_request("https://example.com/");
    let offered = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));
    let_delay_pass(&state, &clock);
    let decision = approve(&state, &offered, "login-a");
    complete_fill_in_state(
        &vault.state,
        &effects,
        &request,
        &offered.approval,
        decision,
        &|| true,
    );
    let mut save = save_request("new");
    let offered = offer(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut save,
    ));
    let_delay_pass(&state, &clock);
    resolve_browser_save_in_state(
        &state,
        &vault.state,
        &effects,
        offered.approval.approval_id(),
        true,
        None,
    )
    .expect("saved");

    let page =
        release_record_page_in_state(&vault.state, ReleaseRecordQuery::default()).expect("page");
    assert!(page.entries.len() >= 12);
    let page_json = serde_json::to_string(&page).expect("page json");
    assert!(!page_json.contains(CANARY));
    assert!(!page_json.contains("https://"));
    let record_path = crate::vault::release_record::record_path(vault.path());
    let raw = String::from_utf8(std::fs::read(record_path).expect("record")).expect("utf8");
    assert!(!raw.contains(CANARY));
    assert!(!raw.contains("example.com"));
    assert!(!raw.contains("login-a"));
    for call in effects.calls() {
        if let Effect::RecordBrowserHostRegistration(code) = call {
            assert!(!code.contains("example"));
            assert!(!code.contains("login-a"));
            assert!(!code.contains(CANARY));
        }
    }
}

#[test]
fn the_approval_hint_counts_earlier_fills_of_each_offered_login_on_this_site() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    vault.seed(|payload| {
        let mut entry = VaultEntry::default();
        entry.id = "login-b".to_string();
        entry.title = "Second".to_string();
        entry.url = "https://example.com".to_string();
        entry.username = "fictional-second".to_string();
        entry.password = "fictional-second-secret".to_string();
        payload.entries.push(entry);
    });
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    for round in 0..3 {
        let request = request(
            "fill",
            LOOKALIKE_PROTOCOL_VERSION,
            "https://example.com",
            &format!("fill-{round}"),
        );
        let offered = offer(fill_response_in_state(
            &vault.state,
            &state,
            &effects,
            &request,
        ));
        let_delay_pass(&state, &clock);
        let decision = approve(&state, &offered, "login-a");
        complete_fill_in_state(
            &vault.state,
            &effects,
            &request,
            &offered.approval,
            decision,
            &|| true,
        );
    }
    record(
        &vault.state,
        ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Released)
            .item("login-a", "login")
            .host("other.example.org"),
    );
    record(
        &vault.state,
        ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Denied).host("example.com"),
    );

    let request = request(
        "fill",
        LOOKALIKE_PROTOCOL_VERSION,
        "https://example.com",
        "fill-next",
    );
    let offered = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));
    let hint = release_record_hint_in_state(
        &vault.state,
        &state,
        offered.approval.approval_id(),
        crate::vault::util::unix_timestamp(),
    )
    .expect("hint")
    .expect("pending approval");

    assert_eq!(hint.host, "example.com");
    let first = hint
        .items
        .iter()
        .find(|item| item.item_id == "login-a")
        .expect("login-a");
    let second = hint
        .items
        .iter()
        .find(|item| item.item_id == "login-b")
        .expect("login-b");
    assert_eq!(first.released_here, 3);
    assert!(first.last_released_at.is_some());
    assert_eq!(second.released_here, 0);
    assert_eq!(hint.denied_recently, 1);
    assert!(!hint.incomplete);

    assert!(
        release_record_hint_in_state(&vault.state, &state, "not-pending", 0)
            .expect("hint")
            .is_none()
    );
}

#[test]
fn the_approval_hint_ignores_denials_older_than_two_weeks() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    let (state, _) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    record(
        &vault.state,
        ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Denied).host("example.com"),
    );
    let offered = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &fill_request("https://example.com"),
    ));
    let later =
        crate::vault::util::unix_timestamp() + super::release_record::RECENT_DENIAL_SECS + 60;

    let hint =
        release_record_hint_in_state(&vault.state, &state, offered.approval.approval_id(), later)
            .expect("hint")
            .expect("pending");

    assert_eq!(hint.denied_recently, 0);
}

#[test]
fn clearing_the_record_needs_presence_and_leaves_one_entry() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    let presence = ReleasePresence::default();
    for _ in 0..3 {
        record(
            &vault.state,
            ReleaseDraft::new(EntryKind::Copy, Outcome::Released).item("login-a", "login"),
        );
    }

    let refused = clear_release_record_in_state(&vault.state, &presence);
    assert_eq!(refused, Err(crate::release::PRESENCE_REQUIRED.to_string()));
    assert_eq!(entries(&vault.state).len(), 3);

    grant(&vault, &presence);
    clear_release_record_in_state(&vault.state, &presence).expect("cleared");
    let entry = only(&vault.state);
    assert_eq!(entry.kind, EntryKind::Cleared);
    assert_eq!(entry.count, 3);
}

#[test]
fn retention_accepts_only_the_offered_choices() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    assert!(set_release_record_retention_in_state(&vault.state, 3).is_err());
    assert!(set_release_record_retention_in_state(&vault.state, 4_000).is_err());
    let status = set_release_record_retention_in_state(&vault.state, 90).expect("set");
    assert_eq!(status.retention_days, 90);
    assert_eq!(vault.state.release_record.retention_days(), 90);
}

#[test]
fn a_shorter_retention_removes_older_entries_at_once() {
    let vault = TestVault::with_login("login-a", "https://example.com");
    let now = crate::vault::util::unix_timestamp();
    let mut old = ReleaseDraft::new(EntryKind::Copy, Outcome::Released).item("old", "login");
    old.at = Some(now - 60 * 86_400);
    record(&vault.state, old);
    record(
        &vault.state,
        ReleaseDraft::new(EntryKind::Copy, Outcome::Released).item("new", "login"),
    );

    set_release_record_retention_in_state(&vault.state, 30).expect("set");

    assert_eq!(only(&vault.state).item_id.as_deref(), Some("new"));
}
