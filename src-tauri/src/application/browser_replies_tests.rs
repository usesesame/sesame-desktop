use std::time::Instant;

use crate::application::broker_tests::{let_delay_pass, state_with_clock};
use crate::application::tests::{Effect, FakeEffects};
use crate::browser_protocol::{
    fill_carries_match_kind, BrowserRequest, BrowserResponse, CAPABILITIES_PROTOCOL_VERSION,
    CARD_PROTOCOL_VERSION, LOOKALIKE_PROTOCOL_VERSION, MAX_CREDENTIAL_FIELD_BYTES,
    MAX_NATIVE_MESSAGE_BYTES, PROTOCOL_VERSION, TOTP_PROTOCOL_VERSION,
};
use crate::commands::test_support::TestVault;
use crate::vault::{Card, Identity, VaultEntry};

use super::browser_fill::{
    ApprovalDecision, ApprovalKind, BrowserTotpRequestEvent, NormalizedOrigin, OriginMatchKind,
};
use super::browser_fill_broker::{
    ApprovalEvent, ApprovalRequest, BrowserFillState, APPROVAL_TIMEOUT,
};
use super::browser_replies::{
    activation_response_in_state, capabilities_response, card_response_in_state,
    complete_card_in_state, complete_fill_in_state, complete_identity_in_state,
    complete_totp_in_state, fill_response_in_state, identity_response_in_state, lookalike_host,
    matching_entries, matching_totp_entries, save_response_in_state, totp_response_for_secret,
    totp_response_in_state, BrowserReply, MAX_MATCHING_CANDIDATES,
};

const CANARY_PASSWORD: &str = "fictional-stored-secret";
const CANARY_NEW_PASSWORD: &str = "fictional-new-secret";
const RFC_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn fill_request(origin: &str) -> BrowserRequest {
    BrowserRequest {
        version: LOOKALIKE_PROTOCOL_VERSION,
        message_type: "fill".to_string(),
        request_id: "fill-1".to_string(),
        origin: Some(origin.to_string()),
        fields: None,
        username: None,
        password: None,
        title: None,
        kind: None,
    }
}

fn save_request(origin: &str) -> BrowserRequest {
    BrowserRequest {
        version: PROTOCOL_VERSION,
        message_type: "save".to_string(),
        request_id: "save-1".to_string(),
        origin: Some(origin.to_string()),
        fields: None,
        username: Some("fictional-user".to_string()),
        password: Some(CANARY_NEW_PASSWORD.to_string()),
        title: Some("Northwind".to_string()),
        kind: Some("update".to_string()),
    }
}

fn card_request(origin: &str, fields: &str) -> BrowserRequest {
    BrowserRequest {
        version: CARD_PROTOCOL_VERSION,
        message_type: "card".to_string(),
        request_id: "card-1".to_string(),
        origin: Some(origin.to_string()),
        fields: Some(fields.to_string()),
        username: None,
        password: None,
        title: None,
        kind: None,
    }
}

fn wire(response: &BrowserResponse) -> String {
    String::from_utf8(response.to_zeroizing_bytes().expect("encodes").to_vec()).expect("utf8")
}

#[test]
fn capabilities_answer_desktop_availability_for_its_own_version() {
    let request = BrowserRequest {
        version: CAPABILITIES_PROTOCOL_VERSION,
        message_type: "capabilities".to_string(),
        request_id: "capabilities-1".to_string(),
        origin: None,
        fields: None,
        username: None,
        password: None,
        title: None,
        kind: None,
    };
    assert!(request.validate());

    let response = capabilities_response(&request);

    assert_eq!(response.message_type, "capabilities");
    assert_eq!(response.request_id, "capabilities-1");
    assert_eq!(response.installed, Some(true));
    assert_eq!(response.desktop_available, Some(true));
    assert!(response.validate_for(&request));
}

#[test]
fn activation_asks_for_the_window_once_within_the_activation_interval() {
    let state = BrowserFillState::default();
    let request = BrowserRequest {
        version: PROTOCOL_VERSION,
        message_type: "activate".to_string(),
        request_id: "activate-1".to_string(),
        origin: None,
        fields: None,
        username: None,
        password: None,
        title: None,
        kind: None,
    };
    assert!(request.validate());
    let now = Instant::now();

    let first = activation_response_in_state(&state, &request, now);
    let second = activation_response_in_state(&state, &request, now);

    assert!(first.show_window);
    assert_eq!(first.response.message_type, "activated");
    assert_eq!(first.response.opened, Some(true));
    assert!(first.response.validate_for(&request));
    assert!(!second.show_window);
    assert_eq!(second.response.opened, Some(false));
    assert!(second.response.validate_for(&request));
}

#[test]
fn a_fill_for_a_lookalike_origin_offers_no_candidates() {
    let vault = TestVault::with_login("login-apple", "https://apple.com");
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request("https://\u{0430}pple.com");

    let response = match fill_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Response(response) => *response,
        BrowserReply::Approval(_) => panic!("a lookalike origin offered candidates"),
    };

    assert_eq!(response.message_type, "fill-unavailable");
    assert_eq!(response.reason.as_deref(), Some("lookalike"));
    assert_eq!(response.lookalike.as_deref(), Some("apple.com"));
    assert!(response.username.is_none());
    assert!(response.password.is_none());
    assert!(state.pending_fill_request().is_none());
    assert!(!wire(&response).contains(CANARY_PASSWORD));
}

#[test]
fn a_fill_on_a_locked_vault_answers_no_match_and_releases_nothing() {
    let vault = TestVault::with_login("login-apple", "https://apple.com");
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let epoch = vault.state.session_epoch();
    *vault.state.session.lock().expect("session lock") = None;
    let request = fill_request("https://apple.com");

    let response = match fill_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Response(response) => *response,
        BrowserReply::Approval(_) => panic!("a locked vault offered candidates"),
    };

    assert_eq!(response.message_type, "fill-unavailable");
    assert_eq!(response.reason.as_deref(), Some("noMatch"));
    assert!(response.username.is_none());
    assert!(response.password.is_none());
    assert!(state.pending_fill_request().is_none());
    assert_eq!(vault.state.session_epoch(), epoch);
    assert_eq!(
        effects.calls(),
        vec![
            Effect::RecordBrowserHostRegistration("fill_requested".to_string()),
            Effect::RecordBrowserHostRegistration("fill_locked".to_string()),
        ]
    );
}

#[test]
fn a_fill_approval_that_outlives_the_vault_lock_releases_nothing() {
    let vault = TestVault::with_login("login-a", "https://example.test");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request("https://example.test");
    let offer = match fill_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no fill approval was offered"),
    };
    let_delay_pass(&state, &clock);
    state
        .decide(
            &offer.approval.approval_id,
            ApprovalDecision::Selected("login-a".to_string()),
        )
        .expect("approved");
    let decision = offer.receiver.recv().expect("decision");
    *vault.state.session.lock().expect("session lock") = None;

    let response = complete_fill_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    );

    assert_eq!(response.message_type, "fill-unavailable");
    assert_eq!(response.reason.as_deref(), Some("locked"));
    assert!(response.username.is_none());
    assert!(response.password.is_none());
    assert_eq!(
        effects.calls().last(),
        Some(&Effect::EmitBrowserApprovalCancelled {
            kind: ApprovalKind::Fill,
            approval_id: offer.approval.approval_id.clone(),
            reason: "vaultChanged",
        })
    );
}

#[test]
fn a_denied_fill_approval_releases_no_secret() {
    let vault = TestVault::with_login("login-a", "https://example.test");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request("https://example.test");
    let offer = match fill_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no fill approval was offered"),
    };
    let_delay_pass(&state, &clock);
    state
        .decide(&offer.approval.approval_id, ApprovalDecision::Denied)
        .expect("denied");
    let decision = offer.receiver.recv().expect("decision");

    let response = complete_fill_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    );

    assert_eq!(response.message_type, "fill-unavailable");
    assert_eq!(response.reason.as_deref(), Some("approvalDeclined"));
    assert!(response.username.is_none());
    assert!(response.password.is_none());
    assert!(!wire(&response).contains(CANARY_PASSWORD));
}

#[test]
fn a_timed_out_fill_approval_can_no_longer_be_decided_and_releases_nothing() {
    let vault = TestVault::with_login("login-a", "https://example.test");
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request("https://example.test");
    let offer = match fill_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no fill approval was offered"),
    };
    state.expire_pending();

    assert_eq!(
        state.decide(
            &offer.approval.approval_id,
            ApprovalDecision::Selected("login-a".to_string()),
        ),
        Err("approvalExpired")
    );
    assert!(state.pending_fill_request().is_none());
    assert!(offer.receiver.try_recv().is_err());

    let response = complete_fill_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        ApprovalDecision::Denied,
        &|| true,
    );

    assert_eq!(response.message_type, "fill-unavailable");
    assert_eq!(response.reason.as_deref(), Some("approvalDeclined"));
    assert!(response.username.is_none());
    assert!(response.password.is_none());
}

#[test]
fn a_card_approval_releases_only_the_requested_fields() {
    let vault = TestVault::with_login("login-a", "https://example.test");
    vault.seed(|payload| {
        let mut card = Card::default();
        card.id = "card-a".to_string();
        card.title = "Fictional Visa".to_string();
        card.brand = "Visa".to_string();
        card.cardholder_name = "Casey Example".to_string();
        card.number = "4111111111111111".to_string();
        card.expiry_month = "04".to_string();
        card.expiry_year = "2031".to_string();
        card.security_code = "123".to_string();
        payload.cards.push(card);
    });
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = card_request("https://checkout.example.test", "number,expiryMonth");
    let offer = match card_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no card approval was offered"),
    };
    let_delay_pass(&state, &clock);
    state
        .decide(
            &offer.approval.approval_id,
            ApprovalDecision::Selected("card-a".to_string()),
        )
        .expect("approved");
    let decision = offer.receiver.recv().expect("decision");

    let response = complete_card_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    );

    assert_eq!(response.message_type, "card");
    assert!(response.validate_for(&request));
    let fields = response.card.as_ref().expect("card fields");
    assert_eq!(fields.number.as_deref(), Some("4111111111111111"));
    assert_eq!(fields.expiry_month.as_deref(), Some("04"));
    assert!(fields.cardholder_name.is_none());
    assert!(fields.expiry_year.is_none());
    assert!(fields.security_code.is_none());
}

#[test]
fn an_identity_approval_releases_only_the_requested_fields() {
    let vault = TestVault::with_login("login-a", "https://example.test");
    vault.seed(|payload| {
        let mut identity = Identity::default();
        identity.id = "identity-a".to_string();
        identity.label = "Fictional identity".to_string();
        identity.full_name = "Casey Example".to_string();
        identity.email = "casey@example.test".to_string();
        identity.phone = "555-0100".to_string();
        payload.identities.push(identity);
    });
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = BrowserRequest {
        version: PROTOCOL_VERSION,
        message_type: "identity".to_string(),
        request_id: "identity-1".to_string(),
        origin: Some("https://example.test".to_string()),
        fields: Some("fullName,email".to_string()),
        username: None,
        password: None,
        title: None,
        kind: None,
    };
    assert!(request.validate());
    let offer = match identity_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no identity approval was offered"),
    };
    let_delay_pass(&state, &clock);
    state
        .decide(
            &offer.approval.approval_id,
            ApprovalDecision::Selected("identity-a".to_string()),
        )
        .expect("approved");
    let decision = offer.receiver.recv().expect("decision");

    let response = complete_identity_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    );

    assert_eq!(response.message_type, "identity");
    assert!(response.validate_for(&request));
    let fields = response.identity.as_ref().expect("identity fields");
    assert_eq!(fields.full_name.as_deref(), Some("Casey Example"));
    assert_eq!(fields.email.as_deref(), Some("casey@example.test"));
    assert!(fields.phone.is_none());
    assert!(fields.address_line1.is_none());
}

#[test]
fn a_totp_approval_releases_a_code_only_for_the_approved_origin() {
    let vault = TestVault::with_login("login-a", "https://bank.test");
    vault.seed(|payload| {
        for entry in &mut payload.entries {
            if entry.id == "login-a" {
                entry.totp = Some(RFC_KEY.to_string());
            }
        }
    });
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = BrowserRequest {
        version: TOTP_PROTOCOL_VERSION,
        message_type: "totp".to_string(),
        request_id: "totp-1".to_string(),
        origin: Some("https://bank.test".to_string()),
        fields: None,
        username: None,
        password: None,
        title: None,
        kind: None,
    };
    assert!(request.validate());
    let offer = match totp_response_in_state(&vault.state, &state, &effects, &request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no totp approval was offered"),
    };
    let_delay_pass(&state, &clock);
    state
        .decide(
            &offer.approval.approval_id,
            ApprovalDecision::Selected("login-a".to_string()),
        )
        .expect("approved");
    let decision = offer.receiver.recv().expect("decision");

    let response = complete_totp_in_state(
        &vault.state,
        &effects,
        &request,
        &offer.approval,
        decision,
        &|| true,
    );

    assert_eq!(response.message_type, "totp");
    assert!(response.validate_for(&request));
    assert!(response
        .code
        .as_deref()
        .is_some_and(|code| !code.is_empty()));
    assert!(response.remaining_seconds.is_some());
    assert!(!wire(&response).contains(RFC_KEY));
}

#[test]
fn a_save_for_an_exact_origin_offers_only_that_login_as_an_update_target() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    vault.seed(|payload| {
        let mut entry = VaultEntry::default();
        entry.id = "login-b".to_string();
        entry.title = "Other".to_string();
        entry.url = "https://other.example".to_string();
        entry.username = "other-user".to_string();
        entry.password = "fictional-other-secret".to_string();
        payload.entries.push(entry);
    });
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let mut request = save_request("https://northwind.example");
    assert!(request.validate());

    let offer = match save_response_in_state(&vault.state, &state, &effects, &mut request) {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(_) => panic!("no save approval was offered"),
    };

    let ApprovalEvent::Save(event) = &offer.approval.event else {
        panic!("the broker did not hold a save approval");
    };
    assert_eq!(event.kind, "update");
    assert_eq!(
        event
            .candidates
            .iter()
            .map(|candidate| (candidate.id.as_str(), candidate.match_kind))
            .collect::<Vec<_>>(),
        vec![("login-a", "exact")]
    );
    assert!(!serde_json::to_string(event)
        .expect("serialized save prompt")
        .contains(CANARY_NEW_PASSWORD));
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
        let mut entry = VaultEntry::default();
        entry.id = id.to_string();
        entry.title = format!("Entry {id}");
        entry.username = "casey".to_string();
        entry.email = "casey@example.test".to_string();
        entry.password = password.to_string();
        entry.url = url.to_string();
        entry
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
                super::super::browser_fill::origin_match_kind(&saved_origin, &requested).is_none(),
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
            let kind = super::super::browser_fill::origin_match_kind(&saved_origin, &requested)
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
            let kind = super::super::browser_fill::origin_match_kind(&saved_origin, &requested)
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
        assert!(super::super::browser_fill::origin_match_kind(
            &local,
            &request("http://localhost:3000/").expect("local")
        )
        .is_some());
        assert!(super::super::browser_fill::origin_match_kind(
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
mod lookalike_tests {
    use super::*;

    const CANARY_PASSWORD: &str = "fictional-canary-password";

    fn origin(value: &str) -> NormalizedOrigin {
        NormalizedOrigin::from_request(value).expect("request origin")
    }

    fn entry(id: &str, url: &str, password: &str) -> VaultEntry {
        let mut entry = VaultEntry::default();
        entry.id = id.to_string();
        entry.title = format!("Entry {id}");
        entry.username = "casey".to_string();
        entry.email = "casey@example.test".to_string();
        entry.password = password.to_string();
        entry.url = url.to_string();
        entry
    }

    fn fill_request(origin: &str) -> BrowserRequest {
        BrowserRequest {
            version: LOOKALIKE_PROTOCOL_VERSION,
            message_type: "fill".to_string(),
            request_id: "fill-lookalike-1".to_string(),
            origin: Some(origin.to_string()),
            fields: None,
            username: None,
            password: None,
            title: None,
            kind: None,
        }
    }

    fn wire(response: &BrowserResponse) -> String {
        String::from_utf8(response.to_zeroizing_bytes().expect("encodes").to_vec()).expect("utf8")
    }

    #[test]
    fn a_cyrillic_homoglyph_host_warns_with_the_stored_host_and_no_credential() {
        let entries = vec![entry("login-apple", "https://apple.com", CANARY_PASSWORD)];
        let requested = origin("https://\u{0430}pple.com");
        assert_eq!(requested.hostname, "xn--pple-43d.com");

        let found = lookalike_host(&entries, &requested).expect("a lookalike");
        assert_eq!(found, "apple.com");

        let request = fill_request("https://\u{0430}pple.com");
        let response = BrowserResponse::lookalike_unavailable(&request, found);
        assert_eq!(response.message_type, "fill-unavailable");
        assert_eq!(response.reason.as_deref(), Some("lookalike"));
        assert!(response.username.is_none());
        assert!(response.password.is_none());
        assert!(response.match_kind.is_none());
        assert!(response.validate_for(&request));
        assert!(!wire(&response).contains(CANARY_PASSWORD));
    }

    #[test]
    fn the_punycode_form_of_the_same_host_warns() {
        let entries = vec![entry("login-apple", "https://apple.com", CANARY_PASSWORD)];
        let found = lookalike_host(&entries, &origin("https://xn--pple-43d.com"));
        assert_eq!(found.as_deref(), Some("apple.com"));
    }

    #[test]
    fn a_mixed_script_label_outside_the_confusables_table_still_warns() {
        let entries = vec![entry(
            "login-example",
            "https://example.test",
            CANARY_PASSWORD,
        )];
        let requested = origin("https://\u{044d}xample.test");
        assert_eq!(requested.hostname, "xn--xample-vtf.test");
        assert_eq!(
            super::super::browser_replies::confusable_skeleton("\u{044d}"),
            "\u{044d}"
        );
        assert_ne!(
            super::super::browser_replies::confusable_skeleton("\u{044d}xample.test"),
            super::super::browser_replies::confusable_skeleton("example.test")
        );

        assert_eq!(
            lookalike_host(&entries, &requested).as_deref(),
            Some("example.test")
        );
        assert_eq!(
            lookalike_host(&entries, &origin("https://zxample.test")),
            None
        );
    }

    #[test]
    fn a_one_edit_typo_on_a_long_domain_warns_and_a_two_edit_short_one_does_not() {
        let long = vec![entry(
            "login-northwind",
            "https://northwind.co.uk",
            CANARY_PASSWORD,
        )];
        assert_eq!(
            lookalike_host(&long, &origin("https://northwine.co.uk")).as_deref(),
            Some("northwind.co.uk")
        );

        let short = vec![entry("login-seldom", "https://seldom.com", CANARY_PASSWORD)];
        assert_eq!(lookalike_host(&short, &origin("https://selfim.com")), None);
    }

    #[test]
    fn a_trailing_dot_origin_fails_before_any_lookalike_check() {
        assert!(NormalizedOrigin::from_request("https://example.test./").is_none());

        let request = fill_request("https://example.test./");
        let response = BrowserResponse::unavailable(&request, "staleRequest");
        assert!(response.validate_for(&request));
        assert!(response.lookalike.is_none());
    }

    #[test]
    fn an_unrelated_domain_is_no_match_not_a_lookalike() {
        let entries = vec![entry(
            "login-example",
            "https://example.test",
            CANARY_PASSWORD,
        )];
        assert_eq!(
            lookalike_host(&entries, &origin("https://unrelated.test")),
            None
        );

        let request = fill_request("https://unrelated.test");
        let response = BrowserResponse::unavailable(&request, "noMatch");
        assert!(response.validate_for(&request));
    }

    #[test]
    fn a_different_subdomain_of_the_stored_host_is_not_a_lookalike() {
        let entries = vec![entry(
            "login-example",
            "https://example.test",
            CANARY_PASSWORD,
        )];
        assert_eq!(
            lookalike_host(&entries, &origin("https://app.example.test")),
            None
        );
        assert_eq!(
            lookalike_host(&entries, &origin("https://www.example.test")),
            None
        );
    }

    #[test]
    fn a_stored_login_without_a_usable_password_still_warns_without_a_credential() {
        let entries = vec![entry("login-apple", "https://apple.com", "")];
        let request = fill_request("https://\u{0430}pple.com");
        let found =
            lookalike_host(&entries, &origin("https://\u{0430}pple.com")).expect("a lookalike");

        let response = BrowserResponse::lookalike_unavailable(&request, found);
        assert!(response.validate_for(&request));
        assert!(!wire(&response).contains("password"));
        assert!(!wire(&response).contains(CANARY_PASSWORD));
    }

    #[test]
    fn a_long_stored_host_truncates_to_the_display_bound() {
        let label = "a".repeat(62);
        let stored_host = format!("{label}.{label}.{}.test", "c".repeat(62));
        let requested_host = format!("{label}.{label}.{}d.test", "c".repeat(61));
        let entries = vec![entry(
            "login-long",
            &format!("https://{stored_host}"),
            CANARY_PASSWORD,
        )];

        let found = lookalike_host(&entries, &origin(&format!("https://{requested_host}")))
            .expect("a lookalike");
        assert_eq!(found, stored_host[..128]);
        assert_eq!(found.chars().count(), 128);

        let request = fill_request(&format!("https://{requested_host}"));
        let response = BrowserResponse::lookalike_unavailable(&request, found);
        assert!(response.validate_for(&request));
        assert!(wire(&response).len() <= MAX_NATIVE_MESSAGE_BYTES);
    }

    #[test]
    fn a_lookalike_answer_is_never_a_fill() {
        let request = fill_request("https://\u{0430}pple.com");
        let response = BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string());
        assert_ne!(response.message_type, "fill");
        assert!(response.validate_for(&request));

        let mut smuggled =
            BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string());
        smuggled.message_type = "fill".to_string();
        assert!(!smuggled.validate_for(&request));

        let mut replay = BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string());
        replay.username = Some("person@example.test".to_string());
        replay.password = Some(CANARY_PASSWORD.to_string());
        assert!(!replay.validate_for(&request));
        assert!(fill_carries_match_kind(LOOKALIKE_PROTOCOL_VERSION));
    }

    #[test]
    fn local_hosts_and_loopback_addresses_never_warn() {
        let entries = vec![entry(
            "login-example",
            "https://example.test",
            CANARY_PASSWORD,
        )];
        for requested in [
            "https://localhost/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "http://localhost:3000/",
        ] {
            assert_eq!(
                lookalike_host(&entries, &origin(requested)),
                None,
                "{requested} warned"
            );
        }
    }

    #[test]
    fn the_lookalike_scan_of_five_thousand_logins_stays_bounded() {
        let entries: Vec<VaultEntry> = (0..5_000)
            .map(|index| {
                entry(
                    &format!("login-{index}"),
                    &format!("https://site-{index}.example.test"),
                    CANARY_PASSWORD,
                )
            })
            .collect();
        let requested = origin("https://\u{0430}pple.com");

        let started = std::time::Instant::now();
        let found = lookalike_host(&entries, &requested);
        let elapsed = started.elapsed();
        eprintln!("lookalike scan of 5000 stored logins: {elapsed:?}");

        assert_eq!(found, None);
        assert!(elapsed < std::time::Duration::from_secs(5));
    }
}

#[cfg(test)]
mod totp_flow_tests {
    use super::*;
    use crate::application::broker_tests::{let_delay_pass, state_with_clock};
    use crate::browser_protocol::TOTP_PROTOCOL_VERSION;

    const RFC_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn origin(value: &str) -> NormalizedOrigin {
        NormalizedOrigin::from_request(value).expect("origin")
    }

    fn ids(values: &[&str]) -> std::collections::HashSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn totp_entry(id: &str, url: &str, seed: Option<&str>) -> VaultEntry {
        let mut entry = VaultEntry::default();
        entry.id = id.to_string();
        entry.title = format!("Entry {id}");
        entry.username = "casey".to_string();
        entry.url = url.to_string();
        entry.totp = seed.map(str::to_string);
        entry
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
    ) -> (String, std::sync::mpsc::Receiver<ApprovalDecision>) {
        let (approval_id, _, receiver) = state
            .begin(
                request_id,
                origin("https://example.test"),
                epoch,
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

        let (state, clock) = state_with_clock();
        let (approval_id, receiver) = begin_totp(&state, "totp-1", 7);
        let_delay_pass(&state, &clock);
        assert_eq!(
            state.decide(
                &approval_id,
                ApprovalDecision::Selected("login-short".to_string()),
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
        let (state, clock) = state_with_clock();
        let (approval_id, receiver) = begin_totp(&state, "totp-1", 7);
        let_delay_pass(&state, &clock);
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
            )
            .expect("decide");
        assert!(
            matches!(receiver.recv(), Ok(ApprovalDecision::Selected(login_id)) if login_id == "login-a")
        );
        assert!(state.pending_totp_request().is_none());
        assert_eq!(
            state.decide(&approval_id, ApprovalDecision::Denied),
            Err("approvalExpired")
        );
        assert!(matches!(
            state.begin(
                "totp-1",
                origin("https://example.test"),
                7,
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
        state.expire_pending();

        assert_eq!(
            state.decide(&approval_id, ApprovalDecision::Denied),
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
            let before = crate::vault::snapshot::current_totp(RFC_KEY).expect("a current code");
            let response = totp_response_for_secret(&request, RFC_KEY).expect("a response");
            let after = crate::vault::snapshot::current_totp(RFC_KEY).expect("a current code");
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
        let candidate = super::super::browser_fill::TotpFillCandidate {
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
