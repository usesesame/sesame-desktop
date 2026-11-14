use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::test_support::TestVault;
use crate::vault::storage::payload_with_saved_login;
use crate::vault::{Card, VaultEntry, VaultPayload};

use super::browser_fill::{
    card_candidate, card_supports_fields, resolve_browser_fill_in_state,
    resolve_browser_save_in_state, selected_card_fields, verify_update_target, ApprovalDecision,
    ApprovalKind, BrowserFillCandidate, NormalizedOrigin, SaveKind,
};
use super::browser_fill_broker::{ApprovalRequest, BrowserFillState, Clock};
use super::tests::{Effect, FakeEffects};

const APPROVAL_EXPIRED: &str = "That browser approval expired or is no longer available.";

struct TestClock {
    now: Mutex<Instant>,
}

impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(Instant::now()),
        })
    }

    fn advance(&self, by: Duration) {
        *self.now.lock().expect("clock") += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> Instant {
        *self.now.lock().expect("clock")
    }
}

fn state_with_clock() -> (BrowserFillState, Arc<TestClock>) {
    let clock = TestClock::new();
    (BrowserFillState::with_clock(clock.clone()), clock)
}

fn let_delay_pass(state: &BrowserFillState, clock: &TestClock) {
    state.window_focus_changed(true);
    clock.advance(Duration::from_secs(1));
}

fn origin(value: &str) -> NormalizedOrigin {
    NormalizedOrigin::from_request(value).expect("origin")
}

fn candidate_ids(values: &[&str]) -> HashSet<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn begin_fill(
    state: &BrowserFillState,
    request_id: &str,
) -> (String, std::sync::mpsc::Receiver<ApprovalDecision>) {
    let (approval_id, _, receiver) = state
        .begin(
            request_id,
            origin("https://example.test"),
            7,
            ApprovalRequest::Fill {
                candidate_ids: candidate_ids(&["login-a"]),
            },
        )
        .expect("begin");
    (approval_id, receiver)
}

fn begin_save(
    state: &BrowserFillState,
    request_id: &str,
    epoch: u64,
    kind: SaveKind,
    candidates: Vec<BrowserFillCandidate>,
) -> (String, std::sync::mpsc::Receiver<ApprovalDecision>) {
    let (approval_id, _, receiver) = state
        .begin(
            request_id,
            origin("https://northwind.example"),
            epoch,
            ApprovalRequest::Save {
                kind,
                title: "Northwind".to_string(),
                username: "fictional-user".to_string(),
                password: Zeroizing::new("fictional-new-secret".to_string()),
                candidates,
            },
        )
        .expect("begin save");
    (approval_id, receiver)
}

fn effects() -> FakeEffects<'static> {
    FakeEffects::new(std::env::temp_dir())
}

fn payload_with_stored_login() -> VaultPayload {
    let mut payload = VaultPayload::default();
    let mut entry = VaultEntry::default();
    entry.id = "login-a".to_string();
    entry.password = "fictional-stored-secret".to_string();
    entry.updated_at = 41;
    entry.password_updated_at = 40;
    entry.revision = 7;
    payload.entries.push(entry);
    payload
}

#[test]
fn an_unknown_or_reused_approval_id_is_refused() {
    let (state, clock) = state_with_clock();
    let effects = effects();

    assert_eq!(
        resolve_browser_fill_in_state(
            &state,
            &effects,
            "not-the-approval",
            Some("login-a".to_string()),
        ),
        Err(APPROVAL_EXPIRED.to_string())
    );
    assert_eq!(
        effects.calls(),
        vec![Effect::EmitBrowserApprovalCancelled {
            kind: ApprovalKind::Fill,
            approval_id: "not-the-approval".to_string(),
            reason: "expired",
        }]
    );

    let (approval_id, _receiver) = begin_fill(&state, "request-1");
    let_delay_pass(&state, &clock);
    assert!(resolve_browser_fill_in_state(
        &state,
        &effects,
        &approval_id,
        Some("login-a".to_string())
    )
    .is_ok());
    assert_eq!(
        resolve_browser_fill_in_state(&state, &effects, &approval_id, Some("login-a".to_string())),
        Err(APPROVAL_EXPIRED.to_string())
    );
    assert_eq!(
        effects.calls(),
        vec![
            Effect::EmitBrowserApprovalCancelled {
                kind: ApprovalKind::Fill,
                approval_id: "not-the-approval".to_string(),
                reason: "expired",
            },
            Effect::RecordBrowserHostRegistration("fill_approved".to_string()),
            Effect::EmitBrowserApprovalCancelled {
                kind: ApprovalKind::Fill,
                approval_id,
                reason: "expired",
            },
        ]
    );
}

#[test]
fn an_expired_approval_id_is_refused() {
    let (state, _clock) = state_with_clock();
    let effects = effects();
    let (approval_id, _receiver) = begin_fill(&state, "request-1");
    state.expire_pending();

    assert_eq!(
        resolve_browser_fill_in_state(&state, &effects, &approval_id, Some("login-a".to_string())),
        Err(APPROVAL_EXPIRED.to_string())
    );
    assert_eq!(
        effects.calls(),
        vec![Effect::EmitBrowserApprovalCancelled {
            kind: ApprovalKind::Fill,
            approval_id,
            reason: "expired",
        }]
    );
}

#[test]
fn a_rejected_approval_clears_the_pending_approval() {
    let (state, clock) = state_with_clock();
    let effects = effects();
    let (approval_id, receiver) = begin_fill(&state, "request-1");
    let_delay_pass(&state, &clock);

    assert!(resolve_browser_fill_in_state(&state, &effects, &approval_id, None).is_ok());
    assert!(matches!(receiver.try_recv(), Ok(ApprovalDecision::Denied)));
    assert_eq!(
        effects.calls(),
        vec![
            Effect::RecordBrowserHostRegistration("fill_denied".to_string()),
            Effect::EmitBrowserApprovalCancelled {
                kind: ApprovalKind::Fill,
                approval_id,
                reason: "denied",
            },
        ]
    );
    assert!(state
        .begin(
            "request-2",
            origin("https://example.test"),
            7,
            ApprovalRequest::Fill {
                candidate_ids: candidate_ids(&["login-a"]),
            },
        )
        .is_ok());
}

#[test]
fn a_save_on_a_locked_vault_fails_and_writes_nothing() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let (approval_id, _receiver) = begin_save(
        &state,
        "save-1",
        vault.state.session_epoch(),
        SaveKind::New,
        Vec::new(),
    );
    let_delay_pass(&state, &clock);
    *vault.state.session.lock().expect("session lock") = None;

    let error = match resolve_browser_save_in_state(
        &state,
        &vault.state,
        &effects,
        &approval_id,
        true,
        None,
    ) {
        Ok(_) => panic!("a locked vault accepted a save"),
        Err(error) => error,
    };

    assert_eq!(error, "Unlock your vault before saving a login.");
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert_eq!(
        vault.stored_login("login-a").password,
        "fictional-stored-secret"
    );
    assert_eq!(
        effects.calls(),
        vec![
            Effect::RecordBrowserHostRegistration("save_denied".to_string()),
            Effect::EmitBrowserApprovalCancelled {
                kind: ApprovalKind::Save,
                approval_id,
                reason: "denied",
            },
        ]
    );
}

#[test]
fn an_update_cannot_target_a_login_outside_the_broker_candidates() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    vault.seed(|payload| {
        let mut entry = VaultEntry::default();
        entry.id = "login-b".to_string();
        entry.title = "Adversary".to_string();
        entry.url = "https://northwind.example".to_string();
        entry.username = "other-user".to_string();
        entry.password = "fictional-other-secret".to_string();
        entry.revision = 1;
        payload.entries.push(entry);
    });
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let epoch = vault.state.session_epoch();
    let (approval_id, _receiver) = begin_save(
        &state,
        "save-1",
        epoch,
        SaveKind::Update,
        vec![crate::test_support::test_update_candidate(
            "login-a",
            "https://northwind.example",
        )],
    );
    let_delay_pass(&state, &clock);

    let error = match resolve_browser_save_in_state(
        &state,
        &vault.state,
        &effects,
        &approval_id,
        true,
        Some("login-b".to_string()),
    ) {
        Ok(_) => panic!("an update outside the candidates was accepted"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        "Choose which saved login this update belongs to before confirming."
    );
    assert_eq!(
        vault.stored_login("login-a").password,
        "fictional-stored-secret"
    );
    assert_eq!(
        vault.stored_login("login-b").password,
        "fictional-other-secret"
    );
    assert_eq!(vault.state.session_epoch(), epoch);
}

#[test]
fn an_approved_update_commits_the_new_password() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let (approval_id, receiver) = begin_save(
        &state,
        "save-1",
        vault.state.session_epoch(),
        SaveKind::Update,
        vec![crate::test_support::test_update_candidate(
            "login-a",
            "https://northwind.example",
        )],
    );
    let_delay_pass(&state, &clock);

    let result = resolve_browser_save_in_state(
        &state,
        &vault.state,
        &effects,
        &approval_id,
        true,
        Some("login-a".to_string()),
    )
    .expect("saved update")
    .expect("save result");

    assert_eq!(result.id, "login-a");
    assert!(matches!(receiver.try_recv(), Ok(ApprovalDecision::Saved)));
    let stored = vault.stored_login("login-a");
    assert_eq!(stored.password, "fictional-new-secret");
    assert_ne!(stored.password_updated_at, 42);
    assert_eq!(stored.revision, 8);
    assert_eq!(
        effects.calls(),
        vec![Effect::RecordBrowserHostRegistration(
            "save_approved".to_string()
        )]
    );
}

#[test]
fn an_approved_update_stamps_both_timestamps_and_bumps_the_revision() {
    let payload = payload_with_stored_login();
    let updated = payload.entries[0].clone();

    let next = payload_with_saved_login(
        &payload,
        updated,
        Some("fictional-new-secret".to_string()),
        9001,
    )
    .expect("saved update");

    assert_eq!(next.entries[0].password, "fictional-new-secret");
    assert_eq!(next.entries[0].updated_at, 9001);
    assert_eq!(next.entries[0].password_updated_at, 9001);
    assert_eq!(next.entries[0].revision, 8);
    assert_eq!(next.history.len(), 1);
}

#[test]
fn an_approved_update_never_keeps_the_retired_password_in_the_login() {
    let payload = payload_with_stored_login();
    let updated = payload.entries[0].clone();

    let next = payload_with_saved_login(
        &payload,
        updated,
        Some("fictional-new-secret".to_string()),
        9001,
    )
    .expect("saved update");

    assert!(!next.entries[0].password.contains("fictional-stored-secret"));
    assert_eq!(next.history.len(), 1);
}

#[test]
fn an_update_target_must_still_match_its_exact_origin() {
    let mut entry = VaultEntry::default();
    entry.id = "login-a".to_string();
    entry.url = "https://northwind.example".to_string();

    assert!(verify_update_target(
        std::slice::from_ref(&entry),
        "https://northwind.example",
        "login-a"
    ));
    assert!(verify_update_target(
        std::slice::from_ref(&entry),
        "https://www.northwind.example",
        "login-a"
    ));
    assert!(!verify_update_target(
        std::slice::from_ref(&entry),
        "https://northwind.example.evil.test",
        "login-a"
    ));
    assert!(!verify_update_target(
        std::slice::from_ref(&entry),
        "https://northwind.example",
        "login-b"
    ));
}

#[test]
fn a_card_fill_releases_only_the_requested_fields() {
    let mut card = Card::default();
    card.id = "card-a".to_string();
    card.title = "Fictional Visa".to_string();
    card.brand = "Visa".to_string();
    card.cardholder_name = "Casey Example".to_string();
    card.number = "4111111111111111".to_string();
    card.expiry_month = "04".to_string();
    card.expiry_year = "2031".to_string();
    card.security_code = "123".to_string();
    let requested = vec!["number".to_string(), "expiryMonth".to_string()];

    assert!(card_supports_fields(&card, &requested));
    assert!(!card_supports_fields(&card, &["unknownField".to_string()]));
    let fields = selected_card_fields(&card, &requested);
    assert_eq!(fields.number.as_deref(), Some("4111111111111111"));
    assert_eq!(fields.expiry_month.as_deref(), Some("04"));
    assert!(fields.cardholder_name.is_none());
    assert!(fields.expiry_year.is_none());
    assert!(fields.security_code.is_none());
    assert_eq!(card_candidate(&card).last_four, "1111");
}
