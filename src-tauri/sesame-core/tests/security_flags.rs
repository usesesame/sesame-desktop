use sesame_core::snapshot::{duplicate_key_counts, issue_kinds_for, password_counts};
use sesame_core::types::{VaultEntry, VaultPayload};

fn login(url: &str, username: &str, password: &str) -> VaultEntry {
    VaultEntry {
        title: "Example".into(),
        url: url.into(),
        username: username.into(),
        password: password.into(),
        ..VaultEntry::default()
    }
}

fn payload(entries: Vec<VaultEntry>) -> VaultPayload {
    VaultPayload {
        entries,
        ..VaultPayload::default()
    }
}

#[test]
fn a_password_used_on_two_sites_is_reported_as_reused_on_both() {
    let payload = payload(vec![
        login("https://one.test", "person", "shared-secret"),
        login("https://two.test", "person", "shared-secret"),
    ]);
    let duplicates = duplicate_key_counts(&payload);
    let passwords = password_counts(&payload);
    for entry in &payload.entries {
        assert!(
            issue_kinds_for(entry, &duplicates, &passwords).contains(&"reused-password"),
            "reuse was not reported for {}",
            entry.url
        );
    }
}

#[test]
fn entries_with_no_password_are_not_treated_as_sharing_one() {
    let payload = payload(vec![
        login("https://one.test", "person", ""),
        login("https://two.test", "person", ""),
    ]);
    let duplicates = duplicate_key_counts(&payload);
    let passwords = password_counts(&payload);
    for entry in &payload.entries {
        assert!(
            !issue_kinds_for(entry, &duplicates, &passwords).contains(&"reused-password"),
            "an empty password was counted as reuse"
        );
    }
}

#[test]
fn a_unique_strong_password_raises_nothing_about_the_password() {
    let payload = payload(vec![login(
        "https://one.test",
        "person",
        "Tr0ub4dor&3-Xanthic-Quilt",
    )]);
    let duplicates = duplicate_key_counts(&payload);
    let passwords = password_counts(&payload);
    let kinds = issue_kinds_for(&payload.entries[0], &duplicates, &passwords);
    for password_issue in [
        "weak-password",
        "common-password",
        "reused-password",
        "compromised-pattern",
        "old-password",
    ] {
        assert!(
            !kinds.contains(&password_issue),
            "a good password was flagged as {kinds:?}"
        );
    }
}

#[test]
fn the_same_account_saved_twice_is_reported_as_a_duplicate() {
    let payload = payload(vec![
        login("https://one.test", "person", "Tr0ub4dor&3-Xanthic-Quilt"),
        login(
            "https://WWW.One.TEST/login",
            "PERSON",
            "Different&Secret-9182",
        ),
    ]);
    let duplicates = duplicate_key_counts(&payload);
    let passwords = password_counts(&payload);
    assert!(
        issue_kinds_for(&payload.entries[0], &duplicates, &passwords).contains(&"duplicate"),
        "the same account written differently was not spotted"
    );
}
