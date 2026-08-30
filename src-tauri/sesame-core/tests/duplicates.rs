use sesame_core::snapshot::{
    duplicate_key, entries_by_duplicate_key, entry_contents_match, is_duplicate_key_eligible,
    should_skip_exact_duplicate,
};
use sesame_core::types::VaultEntry;

fn login(url: &str, username: &str, password: &str) -> VaultEntry {
    VaultEntry {
        title: "Example".into(),
        url: url.into(),
        username: username.into(),
        password: password.into(),
        ..VaultEntry::default()
    }
}

#[test]
fn the_same_account_written_differently_gets_the_same_key() {
    let plain = login("https://example.test", "Person@Example.test", "secret");
    let dressed = login(
        "https://WWW.Example.TEST/login?next=1",
        "person@example.test",
        "secret",
    );
    assert_eq!(duplicate_key(&plain), duplicate_key(&dressed));
}

#[test]
fn different_accounts_on_one_site_stay_separate() {
    let first = login("https://example.test", "alice", "secret");
    let second = login("https://example.test", "bob", "secret");
    assert_ne!(duplicate_key(&first), duplicate_key(&second));
}

#[test]
fn an_entry_with_neither_address_nor_username_is_not_matched_against_anything() {
    let empty = login("", "", "secret");
    assert!(!is_duplicate_key_eligible(&empty));
    assert!(is_duplicate_key_eligible(&login(
        "https://example.test",
        "",
        "secret"
    )));
    assert!(is_duplicate_key_eligible(&login("", "person", "secret")));
}

#[test]
fn importing_the_same_row_twice_skips_the_second_copy() {
    let existing = vec![login("https://example.test", "person", "secret")];
    let index = entries_by_duplicate_key(&existing);
    let again = login("https://example.test", "person", "secret");
    assert!(should_skip_exact_duplicate(&again, &index));
}

#[test]
fn a_changed_password_for_a_known_account_is_not_skipped() {
    let existing = vec![login("https://example.test", "person", "old-secret")];
    let index = entries_by_duplicate_key(&existing);
    let rotated = login("https://example.test", "person", "new-secret");
    assert!(
        !should_skip_exact_duplicate(&rotated, &index),
        "a rotated password would have been discarded"
    );
}

#[test]
fn an_account_that_is_not_in_the_vault_is_never_skipped() {
    let existing = vec![login("https://example.test", "person", "secret")];
    let index = entries_by_duplicate_key(&existing);
    assert!(!should_skip_exact_duplicate(
        &login("https://other.test", "person", "secret"),
        &index
    ));
    assert!(!should_skip_exact_duplicate(
        &login("https://example.test", "someone", "secret"),
        &index
    ));
}

#[test]
fn contents_match_only_when_every_carried_field_agrees() {
    let left = login("https://example.test", "person", "secret");
    assert!(entry_contents_match(&left, &left.clone()));

    let mut noted = left.clone();
    noted.notes = Some("a note".into());
    assert!(!entry_contents_match(&left, &noted));

    let mut coded = left.clone();
    coded.totp = Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
    assert!(!entry_contents_match(&left, &coded));
}
