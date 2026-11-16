use std::time::{Duration, Instant};

use sesame_core::api::open_vault_with_password;

use super::logins::{
    add_items_tag_in_state, bulk_assign_folder_in_state, create_folder_in_state,
    delete_folder_in_state, delete_login_in_state, duplicate_groups_in_state,
    merge_comparison_in_state, merge_duplicate_logins_in_state, record_item_use_in_state,
    refresh_totp_in_state, rename_folder_in_state, reveal_login_secret_in_state,
    save_login_in_state, set_item_favourite_in_state, set_login_folders_in_state,
    totp_codes_in_state, MAX_COMPARED_LOGINS,
};
use crate::release::{ReleasePresence, PRESENCE_REQUIRED};
use crate::test_support::{login_input, TestVault};
use crate::vault::storage::{commit_payload_change, payload_with_saved_login};
use crate::vault::{
    CustomFieldEntry, MergeChoices, MergeDuplicateLoginsRequest, TaggedItem, VaultEntry, VaultFile,
    VaultPayload, VaultState,
};

const MASTER_PASSWORD: &str = "fictional master password";
const HIDDEN_VALUE: &str = "fictional-hidden-canary";
const VISIBLE_VALUE: &str = "fictional member 42";
const TOTP_SEED: &str = "JBSWY3DPEHPK3PXP";
const LOCKED_SAVE: &str = "Unlock your vault before saving a login.";
const LOCKED_DELETE: &str = "Unlock your vault before deleting a login.";
const LOCKED_FOLDERS: &str = "Unlock your vault before organizing folders.";
const LOCKED_ORGANIZE: &str = "Unlock your vault before organizing items.";
const LOCKED_FAVOURITE: &str = "Unlock your vault before changing a favourite.";
const LOCKED_USE: &str = "Unlock your vault before recording item use.";
const LOCKED_MERGE: &str = "Unlock your vault before merging logins.";
const LOCKED_READ: &str = "Unlock your vault first.";
const MISSING_ITEM: &str = "That saved item no longer exists.";
const MISSING_LOGIN: &str = "That saved login no longer exists.";

fn bytes(vault: &TestVault) -> Vec<u8> {
    std::fs::read(vault.path()).expect("vault bytes")
}

fn stored_payload(vault: &TestVault) -> VaultPayload {
    let file: VaultFile = serde_json::from_slice(&bytes(vault)).expect("vault file");
    open_vault_with_password(&file, MASTER_PASSWORD)
        .expect("opened vault")
        .payload
        .clone()
}

fn lock(vault: &TestVault) {
    *vault.state.session.lock().expect("session lock") = None;
}

fn grant(vault: &TestVault, presence: &ReleasePresence) {
    let session = vault.state.session.lock().expect("session lock");
    presence
        .grant_with_password(
            session.as_ref().expect("session"),
            vault.state.session_epoch(),
            MASTER_PASSWORD,
        )
        .expect("granted presence");
}

fn vault_with_duplicates() -> TestVault {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    vault.seed(|payload| {
        let mut second = VaultEntry::default();
        second.id = "login-b".to_string();
        second.title = "Northwind".to_string();
        second.url = "https://northwind.example".to_string();
        second.username = "fictional-user".to_string();
        second.password = "fictional-other-secret".to_string();
        payload.entries.push(second);
    });
    vault
}

fn field(label: &str, value: &str, kind: &str) -> CustomFieldEntry {
    CustomFieldEntry {
        label: label.to_string(),
        value: value.to_string(),
        kind: kind.to_string(),
    }
}

fn custom_fields() -> Vec<CustomFieldEntry> {
    vec![
        field("Member number", VISIBLE_VALUE, "text"),
        field("Security answer", HIDDEN_VALUE, "secret"),
    ]
}

fn field_rows(entry: &VaultEntry) -> Vec<(String, String, String)> {
    entry
        .custom_fields
        .iter()
        .map(|field| (field.label.clone(), field.value.clone(), field.kind.clone()))
        .collect()
}

fn vault_with_custom_fields() -> TestVault {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    vault.seed(|payload| payload.entries[0].custom_fields = custom_fields());
    vault
}

fn merge_request(keep: &str, remove: &[&str]) -> MergeDuplicateLoginsRequest {
    MergeDuplicateLoginsRequest {
        keep_id: keep.to_string(),
        remove_ids: remove.iter().map(|id| id.to_string()).collect(),
        choices: MergeChoices::default(),
    }
}

#[test]
fn saving_a_login_on_a_locked_vault_fails_and_writes_nothing() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();
    lock(&vault);

    let error = save_login_in_state(
        &vault.state,
        login_input(
            Some("login-a"),
            "https://northwind.example",
            "fictional-new-secret",
        ),
    )
    .err()
    .expect("locked vault");

    assert_eq!(error, LOCKED_SAVE);
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
}

#[test]
fn a_rejected_save_leaves_the_vault_file_byte_identical() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);
    let mut input = login_input(
        Some("login-a"),
        "https://northwind.example",
        "fictional-new-secret",
    );
    input.title = "   ".to_string();

    let error = save_login_in_state(&vault.state, input)
        .err()
        .expect("invalid title");

    assert_eq!(error, "Give this login a name so you can find it again.");
    assert_eq!(bytes(&vault), before);
}

#[test]
fn a_save_is_validated_before_the_vault_is_locked_or_touched() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);
    lock(&vault);
    let mut input = login_input(Some("login-a"), "https://northwind.example", "");
    input.totp = Some("!!! not a two factor secret !!!".to_string());

    let error = save_login_in_state(&vault.state, input)
        .err()
        .expect("invalid totp");

    assert_eq!(
        error,
        "The 2FA secret is not valid. Paste a base32 secret or an otpauth:// link."
    );
    assert_eq!(bytes(&vault), before);
}

#[test]
fn a_typed_password_is_committed_to_the_vault_file_and_advances_the_epoch() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let epoch = vault.state.session_epoch();

    let result = save_login_in_state(
        &vault.state,
        login_input(
            Some("login-a"),
            "https://northwind.example",
            "fictional-new-secret",
        ),
    )
    .expect("saved login");

    assert_eq!(result.id, "login-a");
    let stored = vault.stored_login("login-a");
    assert_eq!(stored.password, "fictional-new-secret");
    assert_eq!(stored.revision, 8);
    assert_eq!(vault.state.session_epoch(), epoch + 1);
}

fn vault_with_backup_codes() -> TestVault {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    vault.seed(|payload| {
        payload.entries[0].backup_codes = vec!["fictional-code-1".to_string()];
    });
    vault
}

#[test]
fn a_save_that_keeps_the_backup_codes_leaves_them_as_stored() {
    let vault = vault_with_backup_codes();
    let mut input = login_input(Some("login-a"), "https://northwind.example", "");
    input.keep_backup_codes = true;

    save_login_in_state(&vault.state, input).expect("saved login");

    assert_eq!(
        vault.stored_login("login-a").backup_codes,
        vec!["fictional-code-1"]
    );
}

#[test]
fn a_save_that_does_not_keep_blank_backup_codes_clears_them() {
    let vault = vault_with_backup_codes();

    save_login_in_state(
        &vault.state,
        login_input(Some("login-a"), "https://northwind.example", ""),
    )
    .expect("saved login");

    assert!(vault.stored_login("login-a").backup_codes.is_empty());
}

#[test]
fn typed_backup_codes_replace_the_stored_ones_even_when_keeping_is_requested() {
    let vault = vault_with_backup_codes();
    let mut input = login_input(Some("login-a"), "https://northwind.example", "");
    input.keep_backup_codes = true;
    input.backup_codes = vec!["fictional-new-code".to_string()];

    save_login_in_state(&vault.state, input).expect("saved login");

    assert_eq!(
        vault.stored_login("login-a").backup_codes,
        vec!["fictional-new-code"]
    );
}

#[test]
fn a_blank_password_edit_keeps_the_stored_password() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");

    save_login_in_state(
        &vault.state,
        login_input(Some("login-a"), "https://northwind.example", ""),
    )
    .expect("saved login");

    let stored = vault.stored_login("login-a");
    assert_eq!(stored.password, "fictional-stored-secret");
    assert_eq!(stored.password_updated_at, 42);
}

fn payload_with_one_login() -> VaultPayload {
    let mut payload = VaultPayload::default();
    let mut entry = VaultEntry::default();
    entry.id = "login-a".to_string();
    entry.title = "Northwind".to_string();
    entry.password = "fictional-stored-secret".to_string();
    entry.updated_at = 41;
    entry.password_updated_at = 42;
    entry.revision = 7;
    payload.entries.push(entry);
    payload
}

#[test]
fn a_blank_edit_keeps_the_stored_password_and_its_timestamp() {
    let payload = payload_with_one_login();
    let mut updated = payload.entries[0].clone();
    updated.password = String::new();

    let next = payload_with_saved_login(&payload, updated, None, 9001).expect("saved login");

    assert_eq!(next.entries[0].password, "fictional-stored-secret");
    assert_eq!(next.entries[0].password_updated_at, 42);
    assert_eq!(next.entries[0].updated_at, 9001);
    assert_eq!(next.entries[0].revision, 8);
}

#[test]
fn a_typed_password_replaces_the_stored_one_and_stamps_the_change() {
    let payload = payload_with_one_login();
    let mut updated = payload.entries[0].clone();
    updated.password = "fictional-new-secret".to_string();

    let next = payload_with_saved_login(
        &payload,
        updated,
        Some("fictional-new-secret".to_string()),
        9001,
    )
    .expect("saved login");

    assert_eq!(next.entries[0].password, "fictional-new-secret");
    assert_eq!(next.entries[0].password_updated_at, 9001);
    assert_eq!(next.entries[0].revision, 8);
    assert_eq!(next.history.len(), 1);
}

#[test]
fn an_edit_that_keeps_the_same_password_keeps_its_timestamp() {
    let payload = payload_with_one_login();
    let updated = payload.entries[0].clone();

    let next = payload_with_saved_login(
        &payload,
        updated,
        Some("fictional-stored-secret".to_string()),
        9001,
    )
    .expect("saved login");

    assert_eq!(next.entries[0].password_updated_at, 42);
    assert_eq!(next.entries[0].revision, 8);
}

#[test]
fn an_edit_for_a_missing_login_leaves_the_payload_untouched() {
    let payload = payload_with_one_login();
    let mut updated = VaultEntry::default();
    updated.id = "login-missing".to_string();
    updated.password = "fictional-new-secret".to_string();

    assert!(payload_with_saved_login(&payload, updated, None, 9001).is_err());
    assert_eq!(payload.entries[0].password, "fictional-stored-secret");
    assert_eq!(payload.entries[0].revision, 7);
    assert!(payload.history.is_empty());
}

#[test]
fn the_login_card_counts_backup_codes_and_blanks_hidden_custom_fields() {
    let mut entry = VaultEntry::default();
    entry.backup_codes = vec![
        "fictional-code-1".to_string(),
        "fictional-code-2".to_string(),
    ];
    entry.custom_fields = custom_fields();

    let card = crate::vault::snapshot::login_card_for(&[], &entry);
    let json = serde_json::to_string(&card).expect("serialized card");

    assert_eq!(card.backup_code_count, 2);
    assert!(!json.contains("fictional-code"));
    assert!(!json.contains(HIDDEN_VALUE));
    assert!(json.contains(VISIBLE_VALUE));
    assert_eq!(card.secret_fields, ["field:1"]);
    assert_eq!(card.custom_fields[1].label, "Security answer");
    assert_eq!(card.custom_fields[1].kind, "secret");
    assert!(card.custom_fields[1].value.is_empty());
}

#[test]
fn deleting_a_login_on_a_locked_vault_fails_and_writes_nothing() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();
    lock(&vault);

    let error = delete_login_in_state(&vault.state, "login-a")
        .err()
        .expect("locked vault");

    assert_eq!(error, LOCKED_DELETE);
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
}

#[test]
fn a_blank_login_id_is_rejected_before_the_lock() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    lock(&vault);

    assert_eq!(
        delete_login_in_state(&vault.state, "   ").err(),
        Some("Choose a saved login to delete.".to_string())
    );
}

#[test]
fn deleting_a_missing_login_fails_without_writing() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);

    assert_eq!(
        delete_login_in_state(&vault.state, "login-missing").err(),
        Some(MISSING_LOGIN.to_string())
    );
    assert_eq!(bytes(&vault), before);
}

#[test]
fn deleting_a_login_moves_it_to_the_trash_and_advances_the_epoch() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let epoch = vault.state.session_epoch();

    let result = delete_login_in_state(&vault.state, " login-a ").expect("deleted");

    assert_eq!(result.deleted_id, "login-a");
    assert!(result.snapshot.entries.is_empty());
    assert_eq!(result.snapshot.trash.len(), 1);
    let payload = stored_payload(&vault);
    assert!(payload.entries.is_empty());
    assert_eq!(payload.trash.len(), 1);
    let TaggedItem::Login(entry) = &payload.trash[0].item else {
        panic!("the deleted item is not a login");
    };
    assert_eq!(entry.id, "login-a");
    assert_eq!(vault.state.session_epoch(), epoch + 1);
}

#[test]
fn revealing_needs_a_grant() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");

    let error = reveal_login_secret_in_state(&vault.state, &ReleasePresence::default(), "login-a")
        .expect_err("no grant");

    assert_eq!(error, PRESENCE_REQUIRED);
}

#[test]
fn revealing_works_with_a_current_grant() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);

    let revealed =
        reveal_login_secret_in_state(&vault.state, &presence, "login-a").expect("revealed");

    assert_eq!(revealed.as_str(), "fictional-stored-secret");
}

#[test]
fn an_expired_stale_or_revoked_grant_reveals_nothing() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let presence = ReleasePresence::default();

    presence.grant_until(
        vault.state.session_epoch(),
        Instant::now() - Duration::from_secs(1),
    );
    assert_eq!(
        reveal_login_secret_in_state(&vault.state, &presence, "login-a"),
        Err(PRESENCE_REQUIRED.to_string())
    );

    grant(&vault, &presence);
    vault.state.advance_session_epoch();
    assert_eq!(
        reveal_login_secret_in_state(&vault.state, &presence, "login-a"),
        Err(PRESENCE_REQUIRED.to_string())
    );

    grant(&vault, &presence);
    presence.revoke();
    assert_eq!(
        reveal_login_secret_in_state(&vault.state, &presence, "login-a"),
        Err(PRESENCE_REQUIRED.to_string())
    );
}

#[test]
fn a_locked_vault_reveals_nothing_even_with_a_current_grant() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    lock(&vault);

    assert_eq!(
        reveal_login_secret_in_state(&vault.state, &presence, "login-a"),
        Err(LOCKED_READ.to_string())
    );
}

#[test]
fn creating_renaming_or_deleting_a_folder_needs_an_unlocked_vault() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);
    lock(&vault);

    assert_eq!(
        create_folder_in_state(&vault.state, "Travel").err(),
        Some(LOCKED_FOLDERS.to_string())
    );
    assert_eq!(
        rename_folder_in_state(&vault.state, "fictional-folder", "Trips").err(),
        Some(LOCKED_FOLDERS.to_string())
    );
    assert_eq!(
        delete_folder_in_state(&vault.state, "fictional-folder").err(),
        Some(LOCKED_FOLDERS.to_string())
    );
    assert_eq!(bytes(&vault), before);
}

#[test]
fn creating_a_folder_commits_it_and_advances_the_epoch() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let epoch = vault.state.session_epoch();

    let snapshot = create_folder_in_state(&vault.state, " Travel ").expect("created folder");

    assert_eq!(snapshot.folders.len(), 1);
    assert_eq!(snapshot.folders[0].name, "Travel");
    let payload = stored_payload(&vault);
    assert_eq!(payload.folders.len(), 1);
    assert_eq!(payload.folders[0].name, "Travel");
    assert_eq!(vault.state.session_epoch(), epoch + 1);
}

#[test]
fn renaming_a_folder_keeps_its_id_and_updates_the_name() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let created = create_folder_in_state(&vault.state, "Travel").expect("created folder");
    let folder_id = created.folders[0].id.clone();

    let snapshot = rename_folder_in_state(&vault.state, &format!(" {folder_id} "), "Trips")
        .expect("renamed folder");

    assert_eq!(snapshot.folders[0].id, folder_id);
    assert_eq!(snapshot.folders[0].name, "Trips");
    assert_eq!(stored_payload(&vault).folders[0].name, "Trips");
}

#[test]
fn renaming_or_deleting_a_missing_folder_fails_without_writing() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();

    for error in [
        rename_folder_in_state(&vault.state, "folder-missing", "Trips").err(),
        delete_folder_in_state(&vault.state, "folder-missing").err(),
    ] {
        assert_eq!(error, Some("That folder no longer exists.".to_string()));
    }
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
}

#[test]
fn deleting_a_folder_that_still_holds_logins_keeps_the_logins_and_clears_their_folder() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let assigned = set_login_folders_in_state(&vault.state, vec!["login-a".to_string()], "Travel")
        .expect("filed login");
    let folder_id = assigned.folders[0].id.clone();
    assert_eq!(
        assigned.entries[0].folder_id.as_deref(),
        Some(folder_id.as_str())
    );
    let epoch = vault.state.session_epoch();

    let snapshot = delete_folder_in_state(&vault.state, &folder_id).expect("deleted folder");

    assert!(snapshot.folders.is_empty());
    assert_eq!(snapshot.entries.len(), 1);
    assert!(snapshot.entries[0].folder_id.is_none());
    assert_eq!(snapshot.entries[0].folder, "");
    let payload = stored_payload(&vault);
    assert!(payload.folders.is_empty());
    assert_eq!(payload.entries.len(), 1);
    assert_eq!(payload.entries[0].id, "login-a");
    assert!(payload.entries[0].folder_id.is_none());
    assert_eq!(vault.state.session_epoch(), epoch + 1);
}

#[test]
fn filing_logins_resolves_the_folder_name_and_commits_it() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let epoch = vault.state.session_epoch();

    let snapshot =
        set_login_folders_in_state(&vault.state, vec![" login-a ".to_string()], " Travel ")
            .expect("filed login");

    assert_eq!(snapshot.folders.len(), 1);
    assert_eq!(snapshot.folders[0].name, "Travel");
    assert_eq!(
        snapshot.entries[0].folder_id.as_deref(),
        Some(snapshot.folders[0].id.as_str())
    );
    assert_eq!(snapshot.entries[0].folder, "Travel");
    let payload = stored_payload(&vault);
    assert_eq!(
        payload.entries[0].folder_id.as_deref(),
        Some(payload.folders[0].id.as_str())
    );
    assert_eq!(vault.state.session_epoch(), epoch + 1);
}

#[test]
fn filing_logins_creates_no_folder_when_one_selected_item_is_missing() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();

    let error = set_login_folders_in_state(
        &vault.state,
        vec!["login-a".to_string(), "login-missing".to_string()],
        "Travel",
    )
    .err()
    .expect("missing item");

    assert_eq!(error, "One of the selected items no longer exists.");
    assert!(stored_payload(&vault).folders.is_empty());
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
}

#[test]
fn bulk_assignment_uses_an_existing_folder_and_can_clear_it() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let created = create_folder_in_state(&vault.state, "Travel").expect("created folder");
    let folder_id = created.folders[0].id.clone();

    let assigned =
        bulk_assign_folder_in_state(&vault.state, vec!["login-a".to_string()], Some(&folder_id))
            .expect("assigned folder");
    assert_eq!(
        assigned.entries[0].folder_id.as_deref(),
        Some(folder_id.as_str())
    );

    let cleared = bulk_assign_folder_in_state(&vault.state, vec!["login-a".to_string()], None)
        .expect("cleared folder");
    assert!(cleared.entries[0].folder_id.is_none());
}

#[test]
fn bulk_assignment_refuses_a_missing_folder_without_writing() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);

    assert_eq!(
        bulk_assign_folder_in_state(
            &vault.state,
            vec!["login-a".to_string()],
            Some("folder-missing")
        )
        .err(),
        Some("That folder no longer exists.".to_string())
    );
    assert_eq!(bytes(&vault), before);
}

#[test]
fn adding_a_tag_commits_it_to_the_selected_records() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");

    let snapshot = add_items_tag_in_state(&vault.state, vec!["login-a".to_string()], "  Travel  ")
        .expect("tag added");

    assert_eq!(snapshot.entries[0].tags, vec!["Travel"]);
    assert_eq!(vault.stored_login("login-a").tags, vec!["Travel"]);
}

#[test]
fn an_empty_selection_or_tag_is_rejected_without_touching_the_record() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);

    assert!(add_items_tag_in_state(&vault.state, Vec::new(), "travel").is_err());
    assert!(add_items_tag_in_state(&vault.state, vec!["login-a".to_string()], "   ").is_err());
    assert!(
        add_items_tag_in_state(&vault.state, vec!["login-a".to_string()], &"x".repeat(51)).is_err()
    );
    assert!(add_items_tag_in_state(
        &vault.state,
        vec!["login-a".to_string(), "login-missing".to_string()],
        "travel"
    )
    .is_err());

    let stored = vault.stored_login("login-a");
    assert!(stored.tags.is_empty());
    assert_eq!(stored.updated_at, 41);
    assert_eq!(bytes(&vault), before);
}

#[test]
fn setting_a_favourite_commits_the_flag_and_advances_the_epoch() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let epoch = vault.state.session_epoch();

    let snapshot =
        set_item_favourite_in_state(&vault.state, " login-a ", true).expect("favourite set");

    assert!(snapshot.entries[0].favourite);
    assert!(vault.stored_login("login-a").favourite);
    assert_eq!(vault.state.session_epoch(), epoch + 1);
}

#[test]
fn a_missing_item_is_refused_without_writing() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);

    assert_eq!(
        set_item_favourite_in_state(&vault.state, "login-missing", true).err(),
        Some(MISSING_ITEM.to_string())
    );
    assert_eq!(
        record_item_use_in_state(&vault.state, "login-missing").err(),
        Some(MISSING_ITEM.to_string())
    );
    assert_eq!(bytes(&vault), before);
}

#[test]
fn recording_item_use_stamps_when_it_was_last_used() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let epoch = vault.state.session_epoch();

    let snapshot = record_item_use_in_state(&vault.state, " login-a ").expect("recorded use");

    assert!(snapshot.entries[0].last_used_at.is_some());
    assert!(vault.stored_login("login-a").last_used_at.is_some());
    assert_eq!(vault.state.session_epoch(), epoch + 1);
}

#[test]
fn item_and_folder_operations_need_an_unlocked_vault() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let before = bytes(&vault);
    lock(&vault);

    assert_eq!(
        set_login_folders_in_state(&vault.state, vec!["login-a".to_string()], "Travel").err(),
        Some("Unlock your vault before organizing logins.".to_string())
    );
    assert_eq!(
        bulk_assign_folder_in_state(&vault.state, vec!["login-a".to_string()], None).err(),
        Some(LOCKED_ORGANIZE.to_string())
    );
    assert_eq!(
        add_items_tag_in_state(&vault.state, vec!["login-a".to_string()], "travel").err(),
        Some(LOCKED_ORGANIZE.to_string())
    );
    assert_eq!(
        set_item_favourite_in_state(&vault.state, "login-a", true).err(),
        Some(LOCKED_FAVOURITE.to_string())
    );
    assert_eq!(
        record_item_use_in_state(&vault.state, "login-a").err(),
        Some(LOCKED_USE.to_string())
    );
    assert_eq!(bytes(&vault), before);
}

#[test]
fn duplicate_groups_need_an_unlocked_vault() {
    assert_eq!(
        duplicate_groups_in_state(&VaultState::default()).err(),
        Some(LOCKED_READ.to_string())
    );
}

#[test]
fn duplicate_groups_list_logins_that_share_a_site_and_username() {
    let vault = vault_with_duplicates();

    let groups = duplicate_groups_in_state(&vault.state).expect("duplicate groups");

    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].entries.len(), 2);
    let mut ids = groups[0]
        .entries
        .iter()
        .map(|entry| entry.id.as_str())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    assert_eq!(ids, ["login-a", "login-b"]);
}

#[test]
fn totp_codes_are_derived_sorted_and_never_carry_the_seed() {
    let vault = TestVault::with_login("login-b", "https://northwind.example");
    vault.seed(|payload| {
        payload.entries[0].title = "Zulu".to_string();
        payload.entries[0].totp = Some(TOTP_SEED.to_string());
        let mut first = VaultEntry::default();
        first.id = "login-a".to_string();
        first.title = "Alpha".to_string();
        first.url = "https://northwind.example".to_string();
        first.totp = Some(TOTP_SEED.to_string());
        payload.entries.push(first);
    });

    let codes = totp_codes_in_state(&vault.state).expect("totp codes");

    assert_eq!(codes.len(), 2);
    assert_eq!(
        codes
            .iter()
            .map(|code| code.title.as_str())
            .collect::<Vec<_>>(),
        ["Alpha", "Zulu"]
    );
    assert!(codes
        .iter()
        .all(|code| code.code.len() >= 6 && code.remaining > 0 && code.period > 0));
    let json = serde_json::to_string(&codes).expect("serialized codes");
    assert!(!json.contains(TOTP_SEED));
}

#[test]
fn totp_reads_need_an_unlocked_vault() {
    let state = VaultState::default();

    assert_eq!(
        totp_codes_in_state(&state).err(),
        Some(LOCKED_READ.to_string())
    );
    assert_eq!(
        refresh_totp_in_state(&state, "login-a").err(),
        Some(LOCKED_READ.to_string())
    );
}

#[test]
fn refreshing_a_code_returns_only_derived_values() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    vault.seed(|payload| {
        payload.entries[0].totp = Some(TOTP_SEED.to_string());
    });

    let refresh = refresh_totp_in_state(&vault.state, "login-a").expect("refreshed");

    assert!(refresh.totp_code.is_some());
    assert!(refresh.totp_remaining.is_some());
    let json = serde_json::to_string(&refresh).expect("serialized refresh");
    assert!(!json.contains(TOTP_SEED));
}

#[test]
fn refreshing_a_login_without_a_code_returns_blanks() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");

    let refresh = refresh_totp_in_state(&vault.state, "login-a").expect("refreshed");

    assert_eq!(refresh.totp_code, None);
    assert_eq!(refresh.totp_remaining, None);
}

#[test]
fn refreshing_an_unknown_login_is_refused() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");

    assert_eq!(
        refresh_totp_in_state(&vault.state, "login-missing").err(),
        Some(MISSING_ITEM.to_string())
    );
}

const PASSWORDS: [&str; 2] = ["fictional-bank-password", "fictional-mail-password"];
const SEEDS: [&str; 2] = ["FICTIONALSEEDBANK2222", "FICTIONALSEEDMAIL3333"];
const NOTES: [&str; 2] = ["fictional bank note", "fictional mail note"];

fn vault_with_two_secret_logins() -> TestVault {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    {
        let mut guard = vault.state.session.lock().expect("session lock");
        let session = guard.as_mut().expect("unlocked session");
        let mut payload = session.open_payload().expect("opened payload").clone();
        payload.entries[0].password = PASSWORDS[0].to_string();
        payload.entries[0].totp = Some(SEEDS[0].to_string());
        payload.entries[0].notes = Some(NOTES[0].to_string());
        let mut second = VaultEntry::default();
        second.id = "login-b".to_string();
        second.title = "Northwind".to_string();
        second.url = "https://northwind.example".to_string();
        second.username = "fictional-user".to_string();
        second.password = PASSWORDS[1].to_string();
        second.totp = Some(SEEDS[1].to_string());
        second.notes = Some(NOTES[1].to_string());
        payload.entries.push(second);
        commit_payload_change(session, payload).expect("seeded payload");
    }
    vault
}

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn the_comparison_the_command_returns_holds_no_secret_value() {
    let vault = vault_with_two_secret_logins();

    let comparison =
        merge_comparison_in_state(&vault.state, ids(&["login-a", "login-b"])).expect("comparison");

    let json = serde_json::to_string(&comparison).expect("serialized comparison");
    for secret in PASSWORDS.iter().chain(&SEEDS).chain(&NOTES) {
        assert!(!json.contains(secret), "the comparison leaked {secret}");
    }
    let password = comparison
        .fields
        .iter()
        .find(|field| field.field == "password")
        .expect("password field");
    assert!(password.differs);
    assert!(password.options.iter().all(|option| option.present));
}

#[test]
fn a_repeated_id_is_rejected() {
    let vault = vault_with_two_secret_logins();

    for repeated in [
        ids(&["login-a", "login-a"]),
        ids(&["login-a", "login-b", " login-a "]),
    ] {
        assert_eq!(
            merge_comparison_in_state(&vault.state, repeated).err(),
            Some("Each login can be compared only once.".to_string())
        );
    }
}

#[test]
fn one_id_or_none_is_rejected() {
    let vault = vault_with_two_secret_logins();

    for few in [Vec::new(), ids(&["login-a"])] {
        assert_eq!(
            merge_comparison_in_state(&vault.state, few).err(),
            Some("Choose at least two logins to compare.".to_string())
        );
    }
}

#[test]
fn more_ids_than_the_cap_are_rejected_before_any_login_is_opened() {
    let vault = vault_with_two_secret_logins();
    let many = (0..=MAX_COMPARED_LOGINS)
        .map(|index| format!("login-{index}"))
        .collect::<Vec<_>>();

    assert_eq!(
        merge_comparison_in_state(&vault.state, many).err(),
        Some("Choose at most 16 logins to compare.".to_string())
    );
}

#[test]
fn the_cap_itself_is_accepted_up_to_the_first_missing_login() {
    let vault = vault_with_two_secret_logins();
    let mut at_cap = ids(&["login-a", "login-b"]);
    at_cap.extend((2..MAX_COMPARED_LOGINS).map(|index| format!("missing-{index}")));

    let error = merge_comparison_in_state(&vault.state, at_cap).err();

    assert_ne!(
        error,
        Some("Choose at most 16 logins to compare.".to_string())
    );
    assert!(error.is_some());
}

#[test]
fn a_blank_id_is_rejected() {
    let vault = vault_with_two_secret_logins();

    assert_eq!(
        merge_comparison_in_state(&vault.state, ids(&["login-a", "   "])).err(),
        Some("One of the selected logins is invalid.".to_string())
    );
}

#[test]
fn an_unknown_login_is_rejected() {
    let vault = vault_with_two_secret_logins();

    assert!(merge_comparison_in_state(&vault.state, ids(&["login-a", "missing"])).is_err());
}

#[test]
fn a_locked_vault_is_rejected() {
    let state = VaultState::default();

    assert_eq!(
        merge_comparison_in_state(&state, ids(&["login-a", "login-b"])).err(),
        Some(LOCKED_READ.to_string())
    );
}

#[test]
fn merging_duplicates_commits_the_survivor_and_keeps_a_revision_backup() {
    let vault = vault_with_duplicates();
    let epoch = vault.state.session_epoch();

    let result =
        merge_duplicate_logins_in_state(&vault.state, merge_request("login-a", &["login-b"]))
            .expect("merged logins");

    assert_eq!(result.id, "login-a");
    assert_eq!(result.snapshot.entries.len(), 1);
    assert_eq!(result.snapshot.entries[0].id, "login-a");
    let backup = result.revision_backup_name.expect("revision backup");
    assert!(backup.starts_with("sesame-before-merge-"));
    let payload = stored_payload(&vault);
    assert_eq!(payload.entries.len(), 1);
    assert_eq!(payload.entries[0].id, "login-a");
    assert_eq!(vault.state.session_epoch(), epoch + 1);
}

#[test]
fn merging_a_duplicate_that_changed_meanwhile_fails_without_writing() {
    let vault = vault_with_duplicates();
    vault.seed(|payload| {
        payload.entries[1].username = "fictional-changed-user".to_string();
    });
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();

    let error =
        merge_duplicate_logins_in_state(&vault.state, merge_request("login-a", &["login-b"]))
            .err()
            .expect("changed duplicate");

    assert_eq!(
        error,
        "Only logins for the same website and username can be merged."
    );
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
    assert_eq!(stored_payload(&vault).entries.len(), 2);
}

#[test]
fn merging_a_duplicate_that_was_removed_meanwhile_fails_without_writing() {
    let vault = vault_with_duplicates();
    vault.seed(|payload| {
        payload.entries.retain(|entry| entry.id != "login-b");
    });
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();

    let error =
        merge_duplicate_logins_in_state(&vault.state, merge_request("login-a", &["login-b"]))
            .err()
            .expect("removed duplicate");

    assert_eq!(error, "One of the duplicate logins no longer exists.");
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
    assert_eq!(stored_payload(&vault).entries.len(), 1);
}

#[test]
fn a_merge_request_is_validated_before_the_vault_is_locked_or_touched() {
    let vault = vault_with_duplicates();
    let before = bytes(&vault);
    lock(&vault);

    assert_eq!(
        merge_duplicate_logins_in_state(&vault.state, merge_request("   ", &["login-b"])).err(),
        Some("Choose the login you want to keep.".to_string())
    );
    assert_eq!(
        merge_duplicate_logins_in_state(&vault.state, merge_request("login-a", &[])).err(),
        Some("Choose at least one duplicate to merge.".to_string())
    );
    assert_eq!(bytes(&vault), before);
}

#[test]
fn merging_on_a_locked_vault_fails_and_writes_nothing() {
    let vault = vault_with_duplicates();
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();
    lock(&vault);

    let error =
        merge_duplicate_logins_in_state(&vault.state, merge_request("login-a", &["login-b"]))
            .err()
            .expect("locked vault");

    assert_eq!(error, LOCKED_MERGE);
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
}

fn edited_fields(fields: Vec<CustomFieldEntry>, kept: &[&str]) -> crate::vault::LoginInput {
    let mut input = login_input(Some("login-a"), "https://northwind.example", "");
    input.custom_fields = Some(fields);
    input.kept_secrets = Some(kept.iter().map(|key| key.to_string()).collect());
    input
}

#[test]
fn a_hidden_value_survives_an_edit_that_did_not_retype_it() {
    let vault = vault_with_custom_fields();
    let input = edited_fields(
        vec![
            field("Member number", "fictional member 43", "text"),
            field("Security answer", "", "secret"),
        ],
        &["field:1<-1"],
    );

    save_login_in_state(&vault.state, input).expect("saved login");

    let stored = vault.stored_login("login-a");
    assert_eq!(stored.custom_fields[0].value, "fictional member 43");
    assert_eq!(stored.custom_fields[1].value, HIDDEN_VALUE);
    assert_eq!(stored.password, "fictional-stored-secret");
}

#[test]
fn a_kept_hidden_value_follows_its_row_when_rows_move() {
    let vault = vault_with_custom_fields();
    let input = edited_fields(
        vec![
            field("Security answer", "", "secret"),
            field("Member number", VISIBLE_VALUE, "text"),
        ],
        &["field:0<-1"],
    );

    save_login_in_state(&vault.state, input).expect("saved login");

    let stored = vault.stored_login("login-a");
    assert_eq!(stored.custom_fields[0].value, HIDDEN_VALUE);
    assert_eq!(stored.custom_fields[1].value, VISIBLE_VALUE);
}

#[test]
fn a_hidden_value_is_cleared_when_it_is_not_kept_or_the_row_becomes_visible() {
    let vault = vault_with_custom_fields();
    let input = edited_fields(
        vec![
            field("Security answer", "", "secret"),
            field("Now visible", "", "text"),
        ],
        &["field:1<-1"],
    );

    save_login_in_state(&vault.state, input).expect("saved login");

    let stored = vault.stored_login("login-a");
    assert!(stored
        .custom_fields
        .iter()
        .all(|field| field.value.is_empty()));
}

#[test]
fn removing_a_field_removes_it_from_the_vault() {
    let vault = vault_with_custom_fields();
    let input = edited_fields(vec![field("Member number", VISIBLE_VALUE, "text")], &[]);

    save_login_in_state(&vault.state, input).expect("saved login");

    let stored = vault.stored_login("login-a");
    assert_eq!(
        field_rows(&stored),
        [(
            "Member number".to_string(),
            VISIBLE_VALUE.to_string(),
            "text".to_string()
        )]
    );
    let payload = stored_payload(&vault);
    let current = serde_json::to_string(&payload.entries).expect("entries");
    assert!(!current.contains(HIDDEN_VALUE));
}

#[test]
fn a_save_without_a_field_list_keeps_the_stored_fields() {
    let vault = vault_with_custom_fields();
    let mut input = login_input(Some("login-a"), "https://northwind.example", "");
    input.recovery_not_applicable = true;

    save_login_in_state(&vault.state, input).expect("saved login");

    let stored = vault.stored_login("login-a");
    assert_eq!(
        field_rows(&stored),
        field_rows(&{
            let mut entry = VaultEntry::default();
            entry.custom_fields = custom_fields();
            entry
        })
    );
}

#[test]
fn a_kept_secret_on_a_new_login_takes_nothing_from_another_login() {
    let vault = vault_with_custom_fields();
    let mut input = login_input(None, "https://northwind.example", "fictional-new");
    input.custom_fields = Some(vec![field("Security answer", "", "secret")]);
    input.kept_secrets = Some(vec!["field:0<-1".to_string()]);

    let saved = save_login_in_state(&vault.state, input).expect("saved login");

    assert!(vault.stored_login(&saved.id).custom_fields[0]
        .value
        .is_empty());
}

#[test]
fn a_field_without_a_label_is_refused_without_writing() {
    let vault = vault_with_custom_fields();
    let before = bytes(&vault);
    let input = edited_fields(vec![field(" ", "fictional", "text")], &[]);

    let Err(error) = save_login_in_state(&vault.state, input) else {
        panic!("a field without a label was saved");
    };

    assert_eq!(error, "Give every field a label.");
    assert_eq!(bytes(&vault), before);
}

#[test]
fn history_and_trash_previews_never_carry_a_hidden_value() {
    let vault = vault_with_custom_fields();
    save_login_in_state(
        &vault.state,
        edited_fields(vec![field("Member number", VISIBLE_VALUE, "text")], &[]),
    )
    .expect("saved login");
    let history_id = stored_payload(&vault).history[0].id.clone();
    vault.seed(|payload| payload.entries[0].custom_fields = custom_fields());
    delete_login_in_state(&vault.state, "login-a").expect("deleted login");

    let history =
        crate::application::history::preview_history_version_in_state(&vault.state, &history_id)
            .expect("history preview");
    let trash = crate::application::history::preview_trashed_item_in_state(&vault.state, "login-a")
        .expect("trash preview");
    let snapshot =
        crate::application::records::vault_snapshot_in_state(&vault.state).expect("snapshot");

    for json in [
        serde_json::to_string(&history).expect("history json"),
        serde_json::to_string(&trash).expect("trash json"),
        serde_json::to_string(&snapshot).expect("snapshot json"),
    ] {
        assert!(!json.contains(HIDDEN_VALUE), "{json}");
    }
}

#[test]
fn restoring_from_history_and_trash_brings_the_fields_back() {
    let vault = vault_with_custom_fields();
    save_login_in_state(&vault.state, edited_fields(Vec::new(), &[])).expect("saved login");
    assert!(vault.stored_login("login-a").custom_fields.is_empty());
    let history_id = stored_payload(&vault).history[0].id.clone();

    crate::application::history::restore_history_version_in_state(&vault.state, &history_id)
        .expect("restored version");
    assert_eq!(
        field_rows(&vault.stored_login("login-a")),
        field_rows(&{
            let mut entry = VaultEntry::default();
            entry.custom_fields = custom_fields();
            entry
        })
    );

    delete_login_in_state(&vault.state, "login-a").expect("deleted login");
    crate::application::history::restore_trashed_item_in_state(&vault.state, "login-a")
        .expect("restored item");
    assert_eq!(
        vault.stored_login("login-a").custom_fields[1].value,
        HIDDEN_VALUE
    );
}

#[test]
fn the_merge_comparison_names_custom_fields_without_hidden_values() {
    let vault = vault_with_duplicates();
    vault.seed(|payload| payload.entries[0].custom_fields = custom_fields());

    let comparison = merge_comparison_in_state(
        &vault.state,
        vec!["login-a".to_string(), "login-b".to_string()],
    )
    .expect("comparison");
    let json = serde_json::to_string(&comparison).expect("comparison json");

    assert!(!json.contains(HIDDEN_VALUE));
    assert!(!json.contains(VISIBLE_VALUE));
    let compared = comparison
        .fields
        .iter()
        .find(|field| field.field == "customFields")
        .expect("custom fields row");
    assert!(compared.differs);
    assert_eq!(
        compared.options[0].value.as_deref(),
        Some("Member number, Security answer")
    );
    assert!(!compared.options[1].present);
}

#[test]
fn merging_keeps_the_custom_fields_of_every_merged_login() {
    let vault = vault_with_duplicates();
    vault.seed(|payload| {
        payload.entries[0].custom_fields = vec![field("Member number", VISIBLE_VALUE, "text")];
        payload.entries[1].custom_fields = custom_fields();
    });

    merge_duplicate_logins_in_state(&vault.state, merge_request("login-a", &["login-b"]))
        .expect("merged");

    let merged = vault.stored_login("login-a");
    assert_eq!(merged.custom_fields.len(), 2);
    assert_eq!(merged.custom_fields[1].value, HIDDEN_VALUE);
}

#[test]
fn a_merge_can_take_the_custom_fields_of_one_login() {
    let vault = vault_with_duplicates();
    vault.seed(|payload| {
        payload.entries[0].custom_fields = vec![field("Old", "fictional old", "text")];
        payload.entries[1].custom_fields = custom_fields();
    });
    let mut request = merge_request("login-a", &["login-b"]);
    request.choices.custom_fields = Some("login-b".to_string());

    merge_duplicate_logins_in_state(&vault.state, request).expect("merged");

    let merged = vault.stored_login("login-a");
    assert_eq!(merged.custom_fields.len(), 2);
    assert_eq!(merged.custom_fields[0].label, "Member number");
}

#[test]
fn the_checkup_ignores_custom_fields_when_it_rates_passwords() {
    let vault = vault_with_duplicates();
    vault.seed(|payload| {
        payload.entries[0].password = "fictional-first-login-secret".to_string();
        payload.entries[1].password = "fictional-second-login-secret".to_string();
    });
    let rating = |vault: &TestVault| {
        let snapshot =
            crate::application::records::vault_snapshot_in_state(&vault.state).expect("snapshot");
        let issues = snapshot
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.id.clone(),
                    entry.password_score,
                    entry
                        .password_issues
                        .iter()
                        .map(|issue| issue.kind.to_string())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        (issues, snapshot.security.weak_or_reused)
    };
    let before = rating(&vault);

    vault.seed(|payload| {
        for entry in &mut payload.entries {
            entry.custom_fields = vec![field("PIN", "123456", "secret")];
        }
    });

    assert_eq!(rating(&vault), before);
    assert!(before.0.iter().all(
        |(_, _, issues)| !issues.contains(&"weak-password".to_string())
            && !issues.contains(&"reused-password".to_string())
    ));
}
