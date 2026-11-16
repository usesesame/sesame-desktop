use crate::application::broker_tests::{let_delay_pass, state_with_clock};
use crate::application::tests::FakeEffects;
use crate::browser_protocol::{
    BrowserRequest, BrowserResponse, LOOKALIKE_PROTOCOL_VERSION, PROTOCOL_VERSION,
    SITE_MATCH_PROTOCOL_VERSION, TOTP_PROTOCOL_VERSION,
};
use crate::test_support::{login_input, TestVault};
use crate::vault::{MatchRule, MergeChoices, MergeDuplicateLoginsRequest, VaultEntry};

use super::browser_fill::{
    add_never_save_site_in_state, login_match, never_save_browser_site_in_state, never_save_origin,
    never_save_sites_in_state, remove_never_save_site_in_state, resolve_browser_save_in_state,
    same_site, verify_update_target, ApprovalDecision, NormalizedOrigin, OriginMatchKind,
};
use super::browser_fill_broker::{ApprovalEvent, BrowserFillState};
use super::browser_replies::{
    complete_fill_in_state, complete_totp_in_state, fill_response_in_state, matching_entries,
    matching_totp_entries, save_response_in_state, totp_response_in_state, BrowserApprovalOffer,
    BrowserReply,
};
use super::history::{restore_history_version_in_state, restore_trashed_item_in_state};
use super::logins::{
    delete_login_in_state, merge_comparison_in_state, merge_duplicate_logins_in_state,
    save_login_in_state,
};

const STORED_PASSWORD: &str = "fictional-stored-secret";
const CAPTURED_PASSWORD: &str = "fictional-captured-secret";
const TOTP_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

static NEXT_REQUEST: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

fn request_id(prefix: &str) -> String {
    let next = NEXT_REQUEST.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{prefix}-{next}")
}

fn origin(value: &str) -> NormalizedOrigin {
    NormalizedOrigin::from_request(value).expect("origin")
}

fn entry(id: &str, url: &str, rule: MatchRule) -> VaultEntry {
    let mut entry = VaultEntry::default();
    entry.id = id.to_string();
    entry.title = "Northwind".to_string();
    entry.url = url.to_string();
    entry.username = "fictional-user".to_string();
    entry.password = STORED_PASSWORD.to_string();
    entry.totp = Some(TOTP_SEED.to_string());
    entry.match_rule = rule;
    entry
}

fn kind(entry: &VaultEntry, requested: &str, allow_site: bool) -> Option<OriginMatchKind> {
    login_match(entry, &origin(requested), allow_site).map(|(kind, _)| kind)
}

fn vault_with(rule: MatchRule, url: &str) -> TestVault {
    let vault = TestVault::with_login("login-a", url);
    vault.seed(|payload| {
        payload.entries[0].match_rule = rule;
        payload.entries[0].totp = Some(TOTP_SEED.to_string());
    });
    vault
}

fn set_rule(vault: &TestVault, rule: MatchRule) {
    vault.seed(|payload| payload.entries[0].match_rule = rule);
}

fn fill_request(version: u8, origin: &str) -> BrowserRequest {
    BrowserRequest {
        version,
        message_type: "fill".to_string(),
        request_id: request_id("fill"),
        origin: Some(origin.to_string()),
        fields: None,
        username: None,
        password: None,
        title: None,
        kind: None,
    }
}

fn totp_request(origin: &str) -> BrowserRequest {
    BrowserRequest {
        version: TOTP_PROTOCOL_VERSION,
        message_type: "totp".to_string(),
        request_id: request_id("totp"),
        origin: Some(origin.to_string()),
        fields: None,
        username: None,
        password: None,
        title: None,
        kind: None,
    }
}

fn save_request(origin: &str, kind: &str) -> BrowserRequest {
    BrowserRequest {
        version: PROTOCOL_VERSION,
        message_type: "save".to_string(),
        request_id: request_id("save"),
        origin: Some(origin.to_string()),
        fields: None,
        username: Some("fictional-user".to_string()),
        password: Some(CAPTURED_PASSWORD.to_string()),
        title: Some("Northwind".to_string()),
        kind: Some(kind.to_string()),
    }
}

fn offer(reply: BrowserReply) -> Box<BrowserApprovalOffer> {
    match reply {
        BrowserReply::Approval(offer) => offer,
        BrowserReply::Response(response) => panic!(
            "no approval was offered: {} {:?}",
            response.message_type, response.reason
        ),
    }
}

fn response(reply: BrowserReply) -> BrowserResponse {
    match reply {
        BrowserReply::Response(response) => *response,
        BrowserReply::Approval(_) => panic!("an approval was offered"),
    }
}

fn wire(response: &BrowserResponse) -> String {
    String::from_utf8(response.to_zeroizing_bytes().expect("encodes").to_vec()).expect("utf8")
}

#[test]
fn a_sibling_host_matches_only_a_login_whose_rule_is_site() {
    let site = entry("login-a", "https://app.northwind.test", MatchRule::Site);
    let exact = entry("login-b", "https://app.northwind.test", MatchRule::Exact);

    assert_eq!(
        kind(&site, "https://evil.northwind.test", true),
        Some(OriginMatchKind::Site)
    );
    assert_eq!(
        kind(&site, "https://northwind.test", true),
        Some(OriginMatchKind::Site)
    );
    assert_eq!(kind(&exact, "https://evil.northwind.test", true), None);
    assert_eq!(kind(&site, "https://evil.northwind.test", false), None);
    assert_eq!(
        kind(&site, "https://app.northwind.test", false),
        Some(OriginMatchKind::Exact)
    );
}

#[test]
fn a_private_suffix_tenant_never_matches_another_tenant() {
    let site = entry("login-a", "https://alice.github.io", MatchRule::Site);

    assert_eq!(kind(&site, "https://bob.github.io", true), None);
    assert_eq!(kind(&site, "https://alice.github.io.evil.test", true), None);
    assert_eq!(
        kind(&site, "https://docs.alice.github.io", true),
        Some(OriginMatchKind::Site)
    );
    assert!(!same_site(
        &origin("https://alice.blogspot.com"),
        &origin("https://bob.blogspot.com")
    ));
}

#[test]
fn a_public_suffix_host_never_gets_a_site_match() {
    let saved_suffix = entry("login-a", "https://github.io", MatchRule::Site);
    assert_eq!(kind(&saved_suffix, "https://bob.github.io", true), None);

    let saved_tenant = entry("login-b", "https://shop.example.co.uk", MatchRule::Site);
    assert_eq!(kind(&saved_tenant, "https://co.uk", true), None);
    assert_eq!(kind(&saved_tenant, "https://other.co.uk", true), None);
    assert_eq!(
        kind(&saved_tenant, "https://login.example.co.uk", true),
        Some(OriginMatchKind::Site)
    );

    let saved_tld = entry("login-c", "https://test", MatchRule::Site);
    assert_eq!(kind(&saved_tld, "https://northwind.test", true), None);
}

#[test]
fn ip_addresses_localhost_and_single_label_hosts_never_get_a_site_match() {
    let ipv4 = entry("login-a", "https://192.0.2.10", MatchRule::Site);
    assert_eq!(kind(&ipv4, "https://192.0.2.11", true), None);

    let ipv6 = entry("login-b", "https://[2001:db8::1]", MatchRule::Site);
    assert_eq!(kind(&ipv6, "https://[2001:db8::2]", true), None);

    let local = entry("login-c", "http://localhost:3000", MatchRule::Site);
    assert_eq!(kind(&local, "https://app.localhost:3000", true), None);
    assert_eq!(
        kind(&local, "http://localhost:3000", true),
        Some(OriginMatchKind::Exact)
    );

    let single = entry("login-d", "https://intranet", MatchRule::Site);
    assert_eq!(kind(&single, "https://wiki.intranet", true), None);
}

#[test]
fn a_different_port_or_scheme_never_gets_a_site_match() {
    let site = entry("login-a", "https://northwind.test", MatchRule::Site);
    assert_eq!(kind(&site, "https://login.northwind.test:8443", true), None);

    let custom_port = entry("login-b", "https://northwind.test:8443", MatchRule::Site);
    assert_eq!(
        kind(&custom_port, "https://login.northwind.test", true),
        None
    );
    assert_eq!(
        kind(&custom_port, "https://login.northwind.test:8443", true),
        Some(OriginMatchKind::Site)
    );

    let plain_http = entry("login-c", "http://northwind.test", MatchRule::Site);
    assert_eq!(
        kind(&plain_http, "https://login.northwind.test", true),
        None
    );
    assert!(NormalizedOrigin::from_request("http://login.northwind.test").is_none());
}

#[test]
fn a_site_rule_also_covers_the_other_saved_addresses() {
    let mut site = entry("login-a", "https://northwind.test", MatchRule::Site);
    site.urls = vec!["https://accounts.northwind-id.test/sign-in".to_string()];
    let mut exact = site.clone();
    exact.match_rule = MatchRule::Exact;

    assert_eq!(
        kind(&site, "https://sso.northwind-id.test", true),
        Some(OriginMatchKind::Site)
    );
    assert_eq!(kind(&exact, "https://sso.northwind-id.test", true), None);
    assert_eq!(
        kind(&exact, "https://accounts.northwind-id.test", true),
        None
    );
}

#[test]
fn site_candidates_follow_the_exact_and_alias_ones() {
    let entries = vec![
        entry("site", "https://northwind.test", MatchRule::Site),
        entry("alias", "https://login.northwind.test", MatchRule::Exact),
        entry(
            "exact",
            "https://www.login.northwind.test",
            MatchRule::Exact,
        ),
    ];

    let order = matching_entries(&entries, &origin("https://www.login.northwind.test"), true)
        .into_iter()
        .map(|candidate| (candidate.id, candidate.match_kind))
        .collect::<Vec<_>>();

    assert_eq!(
        order,
        vec![
            ("exact".to_string(), "exact"),
            ("alias".to_string(), "wwwAlias"),
            ("site".to_string(), "site"),
        ]
    );
}

#[test]
fn a_never_login_is_offered_for_nothing() {
    let entries = vec![entry("login-a", "https://northwind.test", MatchRule::Never)];
    let page = origin("https://northwind.test");

    assert!(login_match(&entries[0], &page, true).is_none());
    assert!(matching_entries(&entries, &page, true).is_empty());
    assert!(matching_entries(&entries, &page, false).is_empty());
    assert!(matching_totp_entries(&entries, &page).is_empty());
    assert!(!verify_update_target(
        &entries,
        "https://northwind.test",
        "login-a"
    ));
}

#[test]
fn a_never_login_gets_no_fill_totp_or_update_prompt() {
    let vault = vault_with(MatchRule::Never, "https://northwind.test");
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());

    for version in [LOOKALIKE_PROTOCOL_VERSION, SITE_MATCH_PROTOCOL_VERSION] {
        let request = fill_request(version, "https://northwind.test");
        let answer = response(fill_response_in_state(
            &vault.state,
            &state,
            &effects,
            &request,
        ));
        assert_eq!(answer.reason.as_deref(), Some("noMatch"));
        assert!(!wire(&answer).contains(STORED_PASSWORD));
    }

    let answer = response(totp_response_in_state(
        &vault.state,
        &state,
        &effects,
        &totp_request("https://northwind.test"),
    ));
    assert_eq!(answer.message_type, "totp-unavailable");
    assert_eq!(answer.reason.as_deref(), Some("noMatch"));

    let mut update = save_request("https://northwind.test", "update");
    let answer = response(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut update,
    ));
    assert_eq!(answer.message_type, "save-unavailable");
    assert_eq!(answer.reason.as_deref(), Some("noMatch"));
    assert_eq!(vault.stored_login("login-a").password, STORED_PASSWORD);
}

#[test]
fn a_version_five_request_never_sees_a_site_candidate() {
    let vault = vault_with(MatchRule::Site, "https://northwind.test");
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());

    let old = fill_request(LOOKALIKE_PROTOCOL_VERSION, "https://login.northwind.test");
    let answer = response(fill_response_in_state(&vault.state, &state, &effects, &old));
    assert_eq!(answer.message_type, "fill-unavailable");
    assert_eq!(answer.reason.as_deref(), Some("noMatch"));
    assert!(answer.validate_for(&old));

    let old_exact = fill_request(LOOKALIKE_PROTOCOL_VERSION, "https://northwind.test");
    let approval = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &old_exact,
    ));
    let ApprovalEvent::Fill(event) = approval.approval.event() else {
        panic!("not a fill approval");
    };
    assert_eq!(event.candidates[0].match_kind, "exact");
    state.revoke(approval.approval.approval_id());

    let new = fill_request(SITE_MATCH_PROTOCOL_VERSION, "https://login.northwind.test");
    let approval = offer(fill_response_in_state(&vault.state, &state, &effects, &new));
    let ApprovalEvent::Fill(event) = approval.approval.event() else {
        panic!("not a fill approval");
    };
    assert_eq!(event.candidates[0].match_kind, "site");
    assert_eq!(event.candidates[0].saved_origin, "https://northwind.test");
    assert_eq!(event.origin, "https://login.northwind.test");
}

#[test]
fn a_version_five_approval_cannot_be_completed_as_a_site_match() {
    let vault = vault_with(MatchRule::Site, "https://northwind.test");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let new = fill_request(SITE_MATCH_PROTOCOL_VERSION, "https://login.northwind.test");
    let approval = offer(fill_response_in_state(&vault.state, &state, &effects, &new));
    let_delay_pass(&state, &clock);
    state
        .decide(
            approval.approval.approval_id(),
            ApprovalDecision::Selected("login-a".to_string()),
        )
        .expect("approved");
    let decision = approval.receiver.recv().expect("decision");

    let old = fill_request(LOOKALIKE_PROTOCOL_VERSION, "https://login.northwind.test");
    let answer = complete_fill_in_state(
        &vault.state,
        &effects,
        &old,
        &approval.approval,
        decision,
        &|| true,
    );

    assert_eq!(answer.reason.as_deref(), Some("staleRequest"));
    assert!(answer.password.is_none());
}

#[test]
fn an_approved_site_fill_releases_the_password_with_the_site_rule() {
    let vault = vault_with(MatchRule::Site, "https://northwind.test");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request(SITE_MATCH_PROTOCOL_VERSION, "https://login.northwind.test");
    assert!(request.validate());
    let approval = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));
    let_delay_pass(&state, &clock);
    state
        .decide(
            approval.approval.approval_id(),
            ApprovalDecision::Selected("login-a".to_string()),
        )
        .expect("approved");
    let decision = approval.receiver.recv().expect("decision");

    let answer = complete_fill_in_state(
        &vault.state,
        &effects,
        &request,
        &approval.approval,
        decision,
        &|| true,
    );

    assert_eq!(answer.message_type, "fill");
    assert_eq!(answer.version, SITE_MATCH_PROTOCOL_VERSION);
    assert_eq!(answer.match_kind.as_deref(), Some("site"));
    assert_eq!(answer.password.as_deref(), Some(STORED_PASSWORD));
    assert!(answer.validate_for(&request));
}

fn approved_site_fill(
    vault: &TestVault,
) -> (BrowserRequest, Box<BrowserApprovalOffer>, ApprovalDecision) {
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request(SITE_MATCH_PROTOCOL_VERSION, "https://login.northwind.test");
    let approval = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));
    let_delay_pass(&state, &clock);
    state
        .decide(
            approval.approval.approval_id(),
            ApprovalDecision::Selected("login-a".to_string()),
        )
        .expect("approved");
    let decision = approval.receiver.recv().expect("decision");
    (request, approval, decision)
}

#[test]
fn a_rule_narrowed_while_the_fill_approval_is_open_releases_nothing() {
    for narrowed in [MatchRule::Exact, MatchRule::Never] {
        let vault = vault_with(MatchRule::Site, "https://northwind.test");
        let effects = FakeEffects::new(vault.path().to_path_buf());
        let (request, approval, decision) = approved_site_fill(&vault);
        set_rule(&vault, narrowed);

        let answer = complete_fill_in_state(
            &vault.state,
            &effects,
            &request,
            &approval.approval,
            decision,
            &|| true,
        );

        assert_eq!(answer.message_type, "fill-unavailable");
        assert_eq!(answer.reason.as_deref(), Some("staleRequest"));
        assert!(answer.password.is_none());
        assert!(!wire(&answer).contains(STORED_PASSWORD));
    }
}

#[test]
fn an_edit_that_changes_the_rule_makes_an_open_fill_approval_stale() {
    let vault = vault_with(MatchRule::Site, "https://northwind.test");
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let (request, approval, decision) = approved_site_fill(&vault);
    let mut input = login_input(Some("login-a"), "https://northwind.test", "");
    input.match_rule = Some(MatchRule::Exact);
    save_login_in_state(&vault.state, input).expect("saved edit");

    let answer = complete_fill_in_state(
        &vault.state,
        &effects,
        &request,
        &approval.approval,
        decision,
        &|| true,
    );

    assert_eq!(answer.reason.as_deref(), Some("staleRequest"));
    assert!(answer.password.is_none());
}

#[test]
fn a_never_rule_set_while_a_totp_approval_is_open_releases_no_code() {
    let vault = vault_with(MatchRule::Site, "https://northwind.test");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = totp_request("https://login.northwind.test");
    let approval = offer(totp_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));
    let ApprovalEvent::Totp(event) = approval.approval.event() else {
        panic!("not a totp approval");
    };
    assert_eq!(event.candidates[0].match_kind, "site");
    assert_eq!(event.candidates[0].saved_origin, "https://northwind.test");
    let_delay_pass(&state, &clock);
    state
        .decide(
            approval.approval.approval_id(),
            ApprovalDecision::Selected("login-a".to_string()),
        )
        .expect("approved");
    let decision = approval.receiver.recv().expect("decision");
    set_rule(&vault, MatchRule::Never);

    let answer = complete_totp_in_state(
        &vault.state,
        &effects,
        &request,
        &approval.approval,
        decision,
        &|| true,
    );

    assert_eq!(answer.message_type, "totp-unavailable");
    assert_eq!(answer.reason.as_deref(), Some("staleRequest"));
    assert!(answer.code.is_none());
}

#[test]
fn a_never_rule_set_while_an_update_approval_is_open_changes_no_password() {
    let vault = vault_with(MatchRule::Site, "https://northwind.test");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let mut request = save_request("https://login.northwind.test", "update");
    let approval = offer(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut request,
    ));
    let ApprovalEvent::Save(event) = approval.approval.event() else {
        panic!("not a save approval");
    };
    assert_eq!(event.candidates[0].match_kind, "site");
    let_delay_pass(&state, &clock);
    set_rule(&vault, MatchRule::Never);

    let error = match resolve_browser_save_in_state(
        &state,
        &vault.state,
        &effects,
        approval.approval.approval_id(),
        true,
        Some("login-a".to_string()),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a stale update was saved"),
    };

    assert_eq!(error, "That saved login no longer matches this site.");
    assert_eq!(vault.stored_login("login-a").password, STORED_PASSWORD);
}

#[test]
fn a_site_match_does_not_silence_the_lookalike_warning() {
    let vault = vault_with(MatchRule::Site, "https://northwind-bank.test");
    vault.seed(|payload| {
        payload.entries.push(entry(
            "login-b",
            "https://northwind-banc.test",
            MatchRule::Exact,
        ));
    });
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request(
        SITE_MATCH_PROTOCOL_VERSION,
        "https://login.northwind-bank.test",
    );

    let answer = response(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));

    assert_eq!(answer.reason.as_deref(), Some("lookalike"));
    assert_eq!(answer.lookalike.as_deref(), Some("northwind-banc.test"));
    assert!(answer.validate_for(&request));
    assert!(!wire(&answer).contains(STORED_PASSWORD));
}

#[test]
fn a_lookalike_host_never_gets_a_site_match() {
    let vault = vault_with(MatchRule::Site, "https://apple.com");
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request(
        SITE_MATCH_PROTOCOL_VERSION,
        "https://login.\u{0430}pple.com",
    );

    let answer = response(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));

    assert_eq!(answer.reason.as_deref(), Some("lookalike"));
    assert_eq!(answer.lookalike.as_deref(), Some("apple.com"));
    assert!(answer.password.is_none());
}

#[test]
fn never_save_origins_are_normalized_before_they_are_stored_or_compared() {
    assert_eq!(
        never_save_origin("HTTPS://Northwind.TEST").as_deref(),
        Some("https://northwind.test")
    );
    assert_eq!(
        never_save_origin("https://northwind.test:443").as_deref(),
        Some("https://northwind.test")
    );
    assert_eq!(
        never_save_origin("https://northwind.test:8443").as_deref(),
        Some("https://northwind.test:8443")
    );
    assert_eq!(never_save_origin("https://northwind.test."), None);
    assert_eq!(never_save_origin("https://northwind.test/sign-in"), None);
    assert_eq!(never_save_origin("https://user@northwind.test"), None);
    assert_eq!(never_save_origin("javascript:alert(1)"), None);
}

#[test]
fn a_never_save_origin_is_declined_before_any_prompt_in_every_spelling() {
    let vault = TestVault::with_login("login-a", "https://northwind.test");
    add_never_save_site_in_state(&vault.state, "https://northwind.test").expect("added");
    let state = BrowserFillState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());

    for spelling in [
        "https://northwind.test",
        "HTTPS://NORTHWIND.TEST",
        "https://NorthWind.test:443",
    ] {
        for kind in ["new", "update"] {
            let mut request = save_request(spelling, kind);
            let answer = response(save_response_in_state(
                &vault.state,
                &state,
                &effects,
                &mut request,
            ));
            assert_eq!(answer.message_type, "save-unavailable", "{spelling} {kind}");
            assert_eq!(answer.reason.as_deref(), Some("approvalDeclined"));
            assert!(answer.validate_for(&request));
            assert!(state.pending_save_request().is_none());
        }
    }

    let mut trailing_dot = save_request("https://northwind.test.", "new");
    let answer = response(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut trailing_dot,
    ));
    assert_eq!(answer.reason.as_deref(), Some("staleRequest"));
    assert!(state.pending_save_request().is_none());

    let mut other_port = save_request("https://northwind.test:8443", "new");
    let approval = offer(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut other_port,
    ));
    assert_eq!(
        state.pending_save_request().map(|event| event.origin),
        Some("https://northwind.test:8443".to_string())
    );
    state.revoke(approval.approval.approval_id());

    assert_eq!(vault.stored_login("login-a").password, STORED_PASSWORD);
}

#[test]
fn never_for_this_site_stores_the_brokers_origin_and_declines_the_save() {
    let vault = TestVault::with_login("login-a", "https://northwind.test");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let mut request = save_request("https://Signup.Northwind.TEST:443", "new");
    let approval = offer(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut request,
    ));
    let epoch = vault.state.session_epoch();

    assert!(never_save_browser_site_in_state(
        &state,
        &vault.state,
        &effects,
        approval.approval.approval_id()
    )
    .is_err());
    assert!(never_save_sites_in_state(&vault.state)
        .expect("list")
        .is_empty());

    let_delay_pass(&state, &clock);
    let sites = never_save_browser_site_in_state(
        &state,
        &vault.state,
        &effects,
        approval.approval.approval_id(),
    )
    .expect("never saved");

    assert_eq!(sites, vec!["https://signup.northwind.test".to_string()]);
    assert!(matches!(
        approval.receiver.try_recv(),
        Ok(ApprovalDecision::Denied)
    ));
    assert!(vault.state.session_epoch() > epoch);
    assert!(state.pending_save_request().is_none());
    assert_eq!(vault.stored_login("login-a").password, STORED_PASSWORD);

    let mut again = save_request("https://signup.northwind.test", "new");
    let answer = response(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut again,
    ));
    assert_eq!(answer.reason.as_deref(), Some("approvalDeclined"));

    let sites = remove_never_save_site_in_state(&vault.state, "https://signup.northwind.test")
        .expect("removed");
    assert!(sites.is_empty());
    let mut after_removal = save_request("https://signup.northwind.test", "new");
    let approval = offer(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut after_removal,
    ));
    state.revoke(approval.approval.approval_id());
}

#[test]
fn never_for_this_site_refuses_an_approval_from_an_earlier_session() {
    let vault = TestVault::with_login("login-a", "https://northwind.test");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let mut request = save_request("https://signup.northwind.test", "new");
    let approval = offer(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut request,
    ));
    let_delay_pass(&state, &clock);
    vault.state.advance_session_epoch();

    assert!(never_save_browser_site_in_state(
        &state,
        &vault.state,
        &effects,
        approval.approval.approval_id()
    )
    .is_err());
    assert!(never_save_sites_in_state(&vault.state)
        .expect("list")
        .is_empty());
}

#[test]
fn never_for_this_site_refuses_an_approval_that_is_not_a_save() {
    let vault = TestVault::with_login("login-a", "https://northwind.test");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = fill_request(SITE_MATCH_PROTOCOL_VERSION, "https://northwind.test");
    let approval = offer(fill_response_in_state(
        &vault.state,
        &state,
        &effects,
        &request,
    ));
    let_delay_pass(&state, &clock);

    assert!(never_save_browser_site_in_state(
        &state,
        &vault.state,
        &effects,
        approval.approval.approval_id()
    )
    .is_err());
    assert!(never_save_sites_in_state(&vault.state)
        .expect("list")
        .is_empty());
    assert!(state.pending_fill_request().is_some());
}

#[test]
fn a_site_added_to_the_never_save_list_while_a_save_is_open_is_not_saved() {
    let vault = TestVault::with_login("login-a", "https://northwind.test");
    let (state, clock) = state_with_clock();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let mut request = save_request("https://signup.northwind.test", "new");
    let approval = offer(save_response_in_state(
        &vault.state,
        &state,
        &effects,
        &mut request,
    ));
    let_delay_pass(&state, &clock);
    vault.seed(|payload| {
        payload
            .never_save_sites
            .push("https://signup.northwind.test".to_string())
    });

    let error = match resolve_browser_save_in_state(
        &state,
        &vault.state,
        &effects,
        approval.approval.approval_id(),
        true,
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("a never-save site was saved"),
    };

    assert_eq!(error, "Sesame never saves logins for this site.");
    let session = vault.state.session.lock().expect("session");
    let payload = session
        .as_ref()
        .expect("unlocked")
        .open_payload()
        .expect("payload");
    assert_eq!(payload.entries.len(), 1);
}

#[test]
fn the_never_save_list_is_bounded_and_refuses_what_is_not_an_origin() {
    let vault = TestVault::with_login("login-a", "https://northwind.test");
    assert!(add_never_save_site_in_state(&vault.state, "not an address").is_err());
    assert!(add_never_save_site_in_state(&vault.state, "https://northwind.test/path").is_err());
    vault.seed(|payload| {
        payload.never_save_sites = (0..super::browser_fill::MAX_NEVER_SAVE_SITES)
            .map(|index| format!("https://site-{index}.test"))
            .collect();
    });
    assert!(add_never_save_site_in_state(&vault.state, "https://one-more.test").is_err());
    assert_eq!(
        add_never_save_site_in_state(&vault.state, "https://SITE-1.test")
            .expect("already listed")
            .len(),
        super::browser_fill::MAX_NEVER_SAVE_SITES
    );
}

#[test]
fn an_edit_keeps_the_rule_unless_it_names_one() {
    let vault = vault_with(MatchRule::Site, "https://northwind.test");

    save_login_in_state(
        &vault.state,
        login_input(Some("login-a"), "https://northwind.test", ""),
    )
    .expect("saved edit");
    assert_eq!(vault.stored_login("login-a").match_rule, MatchRule::Site);

    let mut input = login_input(Some("login-a"), "https://northwind.test", "");
    input.match_rule = Some(MatchRule::Never);
    let result = save_login_in_state(&vault.state, input).expect("saved edit");
    assert_eq!(vault.stored_login("login-a").match_rule, MatchRule::Never);
    assert!(!result.snapshot.entries.is_empty());

    let mut new_login = login_input(None, "https://other.test", "fictional-new-secret");
    new_login.match_rule = Some(MatchRule::Site);
    let created = save_login_in_state(&vault.state, new_login).expect("created");
    assert_eq!(vault.stored_login(&created.id).match_rule, MatchRule::Site);
}

#[test]
fn history_restore_and_trash_keep_the_rule() {
    let vault = vault_with(MatchRule::Site, "https://northwind.test");
    let mut input = login_input(Some("login-a"), "https://northwind.test", "");
    input.match_rule = Some(MatchRule::Never);
    save_login_in_state(&vault.state, input).expect("saved edit");

    let history_id = {
        let session = vault.state.session.lock().expect("session");
        let payload = session
            .as_ref()
            .expect("unlocked")
            .open_payload()
            .expect("payload");
        let captured = payload
            .history
            .iter()
            .find(|entry| entry.item.id() == "login-a")
            .expect("captured version");
        let crate::vault::TaggedItem::Login(previous) = &captured.item else {
            panic!("history holds a login");
        };
        assert_eq!(previous.match_rule, MatchRule::Site);
        captured.id.clone()
    };
    restore_history_version_in_state(&vault.state, &history_id).expect("restored");
    assert_eq!(vault.stored_login("login-a").match_rule, MatchRule::Site);

    delete_login_in_state(&vault.state, "login-a").expect("deleted");
    restore_trashed_item_in_state(&vault.state, "login-a").expect("restored from trash");
    assert_eq!(vault.stored_login("login-a").match_rule, MatchRule::Site);
}

#[test]
fn a_merge_keeps_the_kept_rule_unless_another_one_is_chosen() {
    let vault = vault_with(MatchRule::Site, "https://northwind.test");
    vault.seed(|payload| {
        let mut second = entry("login-b", "https://northwind.test", MatchRule::Never);
        second.title = "Northwind".to_string();
        payload.entries.push(second);
    });

    let comparison = merge_comparison_in_state(
        &vault.state,
        vec!["login-a".to_string(), "login-b".to_string()],
    )
    .expect("comparison");
    let field = comparison
        .fields
        .iter()
        .find(|field| field.field == "matchRule")
        .expect("rule is compared");
    assert!(field.differs);
    assert!(!field.secret);
    assert_eq!(
        field
            .options
            .iter()
            .map(|option| option.value.clone().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["Whole site".to_string(), "Never fill".to_string()]
    );

    merge_duplicate_logins_in_state(
        &vault.state,
        MergeDuplicateLoginsRequest {
            keep_id: "login-a".to_string(),
            remove_ids: vec!["login-b".to_string()],
            choices: MergeChoices {
                match_rule: Some("login-b".to_string()),
                ..MergeChoices::default()
            },
        },
    )
    .expect("merged");
    assert_eq!(vault.stored_login("login-a").match_rule, MatchRule::Never);
}

#[test]
fn an_unchosen_merge_keeps_the_rule_of_the_login_that_stays() {
    let vault = vault_with(MatchRule::Site, "https://northwind.test");
    vault.seed(|payload| {
        payload
            .entries
            .push(entry("login-b", "https://northwind.test", MatchRule::Exact));
    });

    merge_duplicate_logins_in_state(
        &vault.state,
        MergeDuplicateLoginsRequest {
            keep_id: "login-a".to_string(),
            remove_ids: vec!["login-b".to_string()],
            choices: MergeChoices::default(),
        },
    )
    .expect("merged");
    assert_eq!(vault.stored_login("login-a").match_rule, MatchRule::Site);
}
