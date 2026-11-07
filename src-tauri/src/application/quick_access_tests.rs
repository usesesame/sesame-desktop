use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::quick_access::{
    copy_quick_access_field_in_state, open_quick_access_item_in_state, quick_access_actions,
    quick_access_field_in_state, quick_access_item, quick_access_matches,
    quick_access_status_in_state, require_quick_access, search_quick_access_items_in_state,
    QUICK_ACCESS_RESULT_LIMIT, QUICK_ACCESS_WINDOW,
};
use super::tests::{grant, Effect, FakeEffects, COPY_EPOCH};
use crate::commands::test_support::TestVault;
use crate::release::{ReleasePresence, PRESENCE_REQUIRED};
use crate::vault::{Card, SoftwareLicense, SshKey, TaggedItem, VaultEntry, WifiNetwork};

const LOCKED: &str = "Unlock your vault in Sesame first.";
const WINDOW_ONLY: &str = "That command is available only from quick access.";
const FIELD_REFUSED: &str = "Quick access cannot copy that field for this item.";
const MISSING_ITEM: &str = "That saved item no longer exists.";

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("sesame-quick-access-{}", crate::vault::random_id()));
        std::fs::write(&path, b"fictional vault file").expect("temp vault file");
        Self { path }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn missing_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "sesame-quick-access-missing-{}",
        crate::vault::random_id()
    ))
}

fn login() -> TaggedItem {
    let mut entry = VaultEntry::default();
    entry.id = "fictional-login".to_string();
    entry.title = "Northwind".to_string();
    entry.username = "casey".to_string();
    entry.password = "fictional-secret-canary".to_string();
    TaggedItem::Login(entry)
}

fn seeded_vault() -> TestVault {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    vault.seed(|payload| {
        let mut card = Card::default();
        card.id = "fictional-card".to_string();
        card.title = "Fictional card".to_string();
        card.number = "4000000000000002".to_string();
        card.security_code = "123".to_string();
        card.expiry_month = "04".to_string();
        card.expiry_year = "2031".to_string();
        payload.cards.push(card);
        let mut network = WifiNetwork::default();
        network.id = "fictional-wifi".to_string();
        network.ssid = "Fictional network".to_string();
        network.password = "fictional-wifi-secret".to_string();
        payload.wifi_networks.push(network);
        let mut license = SoftwareLicense::default();
        license.id = "fictional-license".to_string();
        license.title = "Fictional licence".to_string();
        license.license_key = "fictional-license-key".to_string();
        payload.software_licenses.push(license);
        let mut key = SshKey::default();
        key.id = "fictional-ssh".to_string();
        key.title = "Fictional key".to_string();
        key.public_key = "ssh-ed25519 FICTIONAL".to_string();
        key.private_key = "fictional-private-key".to_string();
        payload.ssh_keys.push(key);
        payload.entries[0].totp = Some("JBSWY3DPEHPK3PXP".to_string());
    });
    vault
}

const GUARDED_FIELDS: [(&str, &str); 6] = [
    ("fictional-login", "password"),
    ("fictional-card", "number"),
    ("fictional-card", "securityCode"),
    ("fictional-wifi", "password"),
    ("fictional-ssh", "privateKey"),
    ("fictional-license", "licenseKey"),
];

#[test]
fn only_the_quick_access_window_passes_the_window_gate() {
    assert!(require_quick_access(QUICK_ACCESS_WINDOW).is_ok());
    assert_eq!(require_quick_access("main"), Err(WINDOW_ONLY.to_string()));
}

#[test]
fn quick_access_status_reports_the_vault_file_and_the_lock_state() {
    let vault = seeded_vault();

    let status = quick_access_status_in_state(&vault.state, &FakeEffects::new(missing_path()))
        .expect("status");
    assert!(!status.exists);
    assert!(status.unlocked);

    let present = TempFile::new();
    let status =
        quick_access_status_in_state(&vault.state, &FakeEffects::new(present.path.clone()))
            .expect("status");
    assert!(status.exists);
    assert!(status.unlocked);

    *vault.state.session.lock().expect("session lock") = None;
    let status =
        quick_access_status_in_state(&vault.state, &FakeEffects::new(present.path.clone()))
            .expect("status");
    assert!(status.exists);
    assert!(!status.unlocked);
}

#[test]
fn every_quick_access_command_that_reads_the_vault_fails_while_locked() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    *vault.state.session.lock().expect("session lock") = None;
    let effects = FakeEffects::new(PathBuf::new());

    assert_eq!(
        search_quick_access_items_in_state(&vault.state, "northwind"),
        Err(LOCKED.to_string())
    );
    assert_eq!(
        copy_quick_access_field_in_state(
            &vault.state,
            &presence,
            &effects,
            "fictional-login",
            "username",
            None,
        ),
        Err(LOCKED.to_string())
    );
    assert_eq!(
        open_quick_access_item_in_state(&vault.state, "fictional-login"),
        Err(LOCKED.to_string())
    );
    assert!(effects.calls().is_empty());
    assert!(vault.state.session.lock().expect("session lock").is_none());

    let status = quick_access_status_in_state(&vault.state, &effects).expect("status while locked");
    assert!(!status.unlocked);
}

#[test]
fn quick_access_result_is_redacted_after_one_record_is_opened() {
    let result = quick_access_item(&login());
    let serialized = serde_json::to_string(&result).expect("serialized quick access item");

    assert!(serialized.contains("Northwind"));
    assert!(serialized.contains("Copy password"));
    assert!(!serialized.contains("fictional-secret-canary"));
}

#[test]
fn search_results_carry_ids_and_display_fields_and_never_a_secret_value() {
    let vault = seeded_vault();
    let items = search_quick_access_items_in_state(&vault.state, "").expect("search");
    let serialized = serde_json::to_string(&items).expect("serialized quick access items");

    assert_eq!(items.len(), 5);
    assert!(items.iter().all(|item| !item.id.is_empty()));
    assert!(serialized.contains("\"id\":\"fictional-login\""));
    assert!(serialized.contains("\"title\":\"Northwind\""));
    assert!(serialized.contains("\"subtitle\":\"fictional-user\""));
    assert!(serialized.contains("\"field\":\"password\""));
    for canary in [
        "fictional-stored-secret",
        "fictional-wifi-secret",
        "fictional-private-key",
        "fictional-license-key",
        "4000000000000002",
        "JBSWY3DPEHPK3PXP",
    ] {
        assert!(
            !serialized.contains(canary),
            "search results contained {canary}"
        );
    }
    assert!(
        !serialized.contains("\"123\""),
        "search results contained the card security code"
    );
}

#[test]
fn quick_access_search_does_not_match_secret_values() {
    assert!(quick_access_matches(&login(), "casey"));
    assert!(!quick_access_matches(&login(), "secret-canary"));
}

#[test]
fn search_never_matches_a_stored_secret() {
    let vault = seeded_vault();
    for query in [
        "fictional-stored-secret",
        "fictional-wifi-secret",
        "fictional-private-key",
        "fictional-license-key",
        "4000000000000002",
        "JBSWY3DPEHPK3PXP",
    ] {
        assert_eq!(
            search_quick_access_items_in_state(&vault.state, query),
            Ok(Vec::new()),
            "query {query}"
        );
    }
}

#[test]
fn search_sorts_results_by_title_and_stops_at_the_limit() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    vault.seed(|payload| {
        for index in 1..=9 {
            let mut entry = VaultEntry::default();
            entry.id = format!("fictional-login-{index:02}");
            entry.title = format!("Fictional {index:02}");
            payload.entries.push(entry);
        }
    });

    let items = search_quick_access_items_in_state(&vault.state, "fictional").expect("search");

    assert_eq!(items.len(), QUICK_ACCESS_RESULT_LIMIT);
    assert_eq!(
        items
            .iter()
            .map(|item| item.title.as_str())
            .collect::<Vec<_>>(),
        [
            "Fictional 01",
            "Fictional 02",
            "Fictional 03",
            "Fictional 04",
            "Fictional 05",
            "Fictional 06",
            "Fictional 07",
            "Fictional 08",
        ]
    );
}

#[test]
fn copying_without_presence_returns_presence_required_and_never_reaches_the_clipboard() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(PathBuf::new());

    assert_eq!(
        copy_quick_access_field_in_state(
            &vault.state,
            &presence,
            &effects,
            "fictional-login",
            "password",
            Some(30_000),
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(effects.calls().is_empty());
}

#[test]
fn copying_passes_the_exact_secret_and_returns_the_effect_epoch() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::new(PathBuf::new());

    let epoch = copy_quick_access_field_in_state(
        &vault.state,
        &presence,
        &effects,
        "fictional-login",
        "password",
        Some(30_000),
    )
    .expect("copied");

    assert_eq!(epoch, COPY_EPOCH);
    assert_eq!(
        effects.calls(),
        vec![Effect::CopySecret {
            value: "fictional-stored-secret".to_string(),
            clear_after_ms: Some(30_000),
        }]
    );
}

#[test]
fn copying_with_an_expired_stale_or_revoked_grant_never_reaches_the_clipboard() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(PathBuf::new());

    presence.grant_until(
        vault.state.session_epoch(),
        Instant::now() - Duration::from_secs(1),
    );
    assert_eq!(
        copy_quick_access_field_in_state(
            &vault.state,
            &presence,
            &effects,
            "fictional-login",
            "password",
            None,
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(effects.calls().is_empty());

    grant(&vault, &presence);
    vault.state.advance_session_epoch();
    assert_eq!(
        copy_quick_access_field_in_state(
            &vault.state,
            &presence,
            &effects,
            "fictional-login",
            "password",
            None,
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(effects.calls().is_empty());

    grant(&vault, &presence);
    presence.revoke();
    assert_eq!(
        copy_quick_access_field_in_state(
            &vault.state,
            &presence,
            &effects,
            "fictional-login",
            "password",
            None,
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(effects.calls().is_empty());
}

#[test]
fn guarded_fields_need_a_master_password_grant() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();

    for (id, field) in GUARDED_FIELDS {
        let error =
            quick_access_field_in_state(&vault.state, &presence, id, field).expect_err("no grant");
        assert_eq!(error, PRESENCE_REQUIRED, "{id} {field}");
    }
}

#[test]
fn guarded_fields_are_released_with_a_current_grant() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();
    grant(&vault, &presence);

    for (id, field) in GUARDED_FIELDS {
        let released = quick_access_field_in_state(&vault.state, &presence, id, field)
            .unwrap_or_else(|error| panic!("{id} {field}: {error}"));
        assert!(!released.is_empty(), "{id} {field}");
    }
}

#[test]
fn an_expired_grant_releases_nothing() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();
    presence.grant_until(
        vault.state.session_epoch(),
        Instant::now() - Duration::from_secs(1),
    );

    for (id, field) in GUARDED_FIELDS {
        let error = quick_access_field_in_state(&vault.state, &presence, id, field)
            .expect_err("expired grant");
        assert_eq!(error, PRESENCE_REQUIRED, "{id} {field}");
    }
}

#[test]
fn a_grant_from_an_earlier_session_epoch_releases_nothing() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    vault.state.advance_session_epoch();

    for (id, field) in GUARDED_FIELDS {
        let error = quick_access_field_in_state(&vault.state, &presence, id, field)
            .expect_err("stale epoch");
        assert_eq!(error, PRESENCE_REQUIRED, "{id} {field}");
    }
}

#[test]
fn a_revoked_grant_releases_nothing() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    presence.revoke();

    for (id, field) in GUARDED_FIELDS {
        let error = quick_access_field_in_state(&vault.state, &presence, id, field)
            .expect_err("revoked grant");
        assert_eq!(error, PRESENCE_REQUIRED, "{id} {field}");
    }
}

#[test]
fn a_locked_vault_releases_nothing() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    *vault.state.session.lock().expect("session lock") = None;

    assert_eq!(
        quick_access_field_in_state(&vault.state, &presence, "fictional-login", "password")
            .map(|value| value.to_string()),
        Err(LOCKED.to_string())
    );
}

#[test]
fn a_field_the_item_does_not_offer_is_refused_even_with_a_grant() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();
    grant(&vault, &presence);

    assert_eq!(
        quick_access_field_in_state(&vault.state, &presence, "fictional-login", "notes")
            .map(|value| value.to_string()),
        Err(FIELD_REFUSED.to_string())
    );
    assert_eq!(
        quick_access_field_in_state(&vault.state, &presence, "fictional-card", "password")
            .map(|value| value.to_string()),
        Err(FIELD_REFUSED.to_string())
    );
}

#[test]
fn fields_without_a_guard_stay_available_with_no_grant() {
    let vault = seeded_vault();
    let presence = ReleasePresence::default();

    for (id, field) in [
        ("fictional-login", "username"),
        ("fictional-login", "totp"),
        ("fictional-card", "expiry"),
        ("fictional-ssh", "publicKey"),
    ] {
        let released = quick_access_field_in_state(&vault.state, &presence, id, field)
            .unwrap_or_else(|error| panic!("{id} {field}: {error}"));
        assert!(!released.is_empty(), "{id} {field}");
    }
}

#[test]
fn every_secret_the_popup_offers_is_guarded_unless_listed_here() {
    let vault = seeded_vault();
    let session = vault.state.session.lock().expect("session lock");
    let session = session.as_ref().expect("session");
    let open_fields = [
        "username",
        "totp",
        "expiry",
        "publicKey",
        "fullName",
        "email",
        "phone",
        "address",
        "open",
    ];
    for id in [
        "fictional-login",
        "fictional-card",
        "fictional-wifi",
        "fictional-ssh",
        "fictional-license",
    ] {
        let item = session.open_item(id).expect("seeded item");
        for action in quick_access_actions(&item) {
            assert_eq!(
                action.guarded,
                !open_fields.contains(&action.field),
                "{id} {}",
                action.field
            );
        }
    }
}

#[test]
fn opening_an_item_returns_the_trimmed_id_and_refuses_a_missing_one() {
    let vault = seeded_vault();

    assert_eq!(
        open_quick_access_item_in_state(&vault.state, " fictional-login "),
        Ok("fictional-login".to_string())
    );
    assert_eq!(
        open_quick_access_item_in_state(&vault.state, "missing"),
        Err(MISSING_ITEM.to_string())
    );
    assert!(vault.state.session.lock().expect("session lock").is_some());
}
