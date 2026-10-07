use std::collections::HashSet;

use tauri::State;

use crate::release::ReleasePresence;
use crate::vault::backup::snapshot_vault_revision;
use crate::vault::imports::{entry_from_input, resolved_totp};
use crate::vault::snapshot::{current_totp, login_card_for, login_summary_for};
use crate::vault::storage::{
    commit_payload_change, materialize_entry_folder, payload_with_added_item_tag,
    payload_with_item_favourite, payload_with_item_folder_id, payload_with_recorded_item_use,
    payload_with_saved_login, payload_without_login,
};
use crate::vault::trash::trash_item;
use crate::vault::util::unix_timestamp;
use crate::vault::{
    DeleteLoginResult, LoginInput, MergeComparison, MergeDuplicateLoginsRequest,
    MergeDuplicateLoginsResult, SaveLoginResult, TaggedItem, VaultPayload, VaultResult,
    VaultSnapshot, VaultState,
};

#[tauri::command]
pub fn get_vault_snapshot(state: State<'_, VaultState>) -> VaultResult<VaultSnapshot> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    Ok(session.snapshot())
}

/// Small on purpose: a shortcut for retyping an address, not a directory.
const MAX_SUGGESTIONS: usize = 8;

/// Deliberate bounded disclosure at the moment of typing, not a session-long leak.
#[tauri::command]
pub fn suggest_field_values(
    field: String,
    state: State<'_, VaultState>,
) -> VaultResult<Vec<String>> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    if !matches!(field.as_str(), "username" | "email") {
        return Ok(Vec::new());
    }
    let index = session.snapshot();
    let ids = index.entries.iter().map(|item| item.id.as_str()).chain(
        index
            .items
            .iter()
            .filter(|item| field == "email" && item.kind == "identity")
            .map(|item| item.id.as_str()),
    );
    let mut seen = HashSet::new();
    let mut suggestions = Vec::new();
    for id in ids {
        let item = session.open_item(id)?;
        let value = match (&*item, field.as_str()) {
            (TaggedItem::Login(entry), "username") => entry.username.as_str(),
            (TaggedItem::Login(entry), "email") => entry.email.as_str(),
            (TaggedItem::Identity(identity), "email") => identity.email.as_str(),
            _ => continue,
        };
        let trimmed = value.trim();
        if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
            continue;
        }
        suggestions.push(trimmed.to_string());
        if suggestions.len() >= MAX_SUGGESTIONS {
            break;
        }
    }
    Ok(suggestions)
}

#[tauri::command]
pub fn get_login_card(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<crate::vault::types::LoginCard> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(&id)?;
    let TaggedItem::Login(entry) = &*item else {
        return Err("That saved login no longer exists.".into());
    };
    let index = session.snapshot();
    Ok(login_card_for(&index.folders, entry))
}

#[tauri::command]
pub fn get_login_summary(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<crate::vault::types::LoginSummary> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(&id)?;
    let TaggedItem::Login(entry) = &*item else {
        return Err("That saved login no longer exists.".into());
    };
    Ok(login_summary_for(entry))
}

#[tauri::command]
pub fn get_duplicate_groups(
    state: State<'_, VaultState>,
) -> VaultResult<Vec<crate::vault::types::DuplicateGroup>> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let index = session.snapshot();
    let mut summaries = Vec::with_capacity(index.entries.len());
    for indexed in &index.entries {
        let item = session.open_item(&indexed.id)?;
        let TaggedItem::Login(entry) = &*item else {
            return Err("That saved login no longer exists.".into());
        };
        summaries.push(login_summary_for(entry));
    }
    Ok(crate::vault::snapshot::duplicate_groups_from_summaries(
        summaries,
    ))
}

/// Every saved code at once, for the authenticator view. Requires an unlocked
/// vault, and returns derived codes only so the seed never crosses the boundary.
#[tauri::command]
pub fn list_totp_codes(
    state: State<'_, VaultState>,
) -> VaultResult<Vec<crate::vault::types::TotpCodeEntry>> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let index = session.snapshot();
    let mut codes = Vec::new();
    for summary in &index.entries {
        let item = session.open_item(&summary.id)?;
        let TaggedItem::Login(entry) = &*item else {
            return Err("That saved login no longer exists.".into());
        };
        let Some((code, remaining, period)) = entry.totp.as_deref().and_then(current_totp) else {
            continue;
        };
        codes.push(crate::vault::types::TotpCodeEntry {
            id: entry.id.clone(),
            title: entry.title.clone(),
            site: crate::vault::util::domain_from_url(&entry.url),
            initials: crate::vault::util::initials_for(&entry.title),
            code,
            remaining,
            period,
        });
    }
    codes.sort_by_key(|code| code.title.to_lowercase());
    Ok(codes)
}

#[tauri::command]
pub fn refresh_totp(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<crate::vault::types::TotpRefresh> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(&id)?;
    let TaggedItem::Login(entry) = &*item else {
        return Err("That saved login no longer exists.".into());
    };
    let (totp_code, totp_remaining) = entry
        .totp
        .as_deref()
        .and_then(current_totp)
        .map_or((None, None), |(code, remaining, _)| {
            (Some(code), Some(remaining))
        });
    Ok(crate::vault::types::TotpRefresh {
        totp_code,
        totp_remaining,
    })
}

#[tauri::command]
pub fn save_login(input: LoginInput, state: State<'_, VaultState>) -> VaultResult<SaveLoginResult> {
    save_login_in_state(input, &state)
}

fn save_login_in_state(input: LoginInput, state: &VaultState) -> VaultResult<SaveLoginResult> {
    let totp_input = input.totp.clone();
    let mut entry = entry_from_input(input)?;
    let entry_id = entry.id.clone();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a login.")?;
    let payload = session.open_payload()?;
    let mut next_payload = payload.clone();
    materialize_entry_folder(&mut next_payload, &mut entry)?;
    if let Some(existing) = next_payload
        .entries
        .iter()
        .find(|saved| saved.id == entry_id)
    {
        let previous = existing.clone();
        let mut updated = entry;
        updated.created_at = if previous.created_at > 0 {
            previous.created_at
        } else {
            updated.created_at
        };
        updated.import_source = previous.import_source.clone();
        updated.legacy_fields = previous.legacy_fields.clone();
        updated.favourite = previous.favourite;
        updated.last_used_at = previous.last_used_at;
        updated.totp = resolved_totp(totp_input, previous.totp.clone());
        let password = (!updated.password.is_empty()).then(|| updated.password.clone());
        next_payload =
            payload_with_saved_login(&next_payload, updated, password, unix_timestamp())?;
    } else {
        next_payload.entries.push(entry);
    }
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveLoginResult {
        id: entry_id,
        snapshot: session.snapshot(),
    })
}

/// Folder names resolve to a stable ID before the payload is committed.
#[tauri::command]
pub fn set_login_folders(
    ids: Vec<String>,
    folder: String,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    let ids = checked_item_ids(ids)?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before organizing logins.")?;
    let payload = session.open_payload()?;
    let next_payload = crate::vault::storage::payload_with_login_folders(&payload, &ids, &folder)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(session.snapshot())
}

#[tauri::command]
pub fn bulk_assign_folder(
    ids: Vec<String>,
    folder_id: Option<String>,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    let ids = checked_item_ids(ids)?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before organizing items.")?;
    let payload = session.open_payload()?;
    let next_payload = payload_with_item_folder_id(&payload, &ids, folder_id.as_deref())?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(session.snapshot())
}

#[tauri::command]
pub fn add_items_tag(
    ids: Vec<String>,
    tag: String,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    add_items_tag_in_state(ids, tag, &state)
}

fn add_items_tag_in_state(
    ids: Vec<String>,
    tag: String,
    state: &VaultState,
) -> VaultResult<VaultSnapshot> {
    let ids = checked_item_ids(ids)?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before organizing items.")?;
    let payload = session.open_payload()?;
    let next_payload = payload_with_added_item_tag(&payload, &ids, &tag)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(session.snapshot())
}

#[tauri::command]
pub fn create_folder(name: String, state: State<'_, VaultState>) -> VaultResult<VaultSnapshot> {
    change_folders(state, |payload| {
        crate::vault::storage::create_folder_in_payload(payload, &name)
    })
}

#[tauri::command]
pub fn rename_folder(
    folder_id: String,
    name: String,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    change_folders(state, |payload| {
        crate::vault::storage::rename_folder_in_payload(payload, folder_id.trim(), &name)
    })
}

#[tauri::command]
pub fn delete_folder(
    folder_id: String,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    change_folders(state, |payload| {
        crate::vault::storage::delete_folder_from_payload(payload, folder_id.trim())
    })
}

fn change_folders(
    state: State<'_, VaultState>,
    change: impl FnOnce(&VaultPayload) -> VaultResult<VaultPayload>,
) -> VaultResult<VaultSnapshot> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before organizing folders.")?;
    let payload = session.open_payload()?;
    let next_payload = change(&payload)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(session.snapshot())
}

fn checked_item_ids(ids: Vec<String>) -> VaultResult<HashSet<String>> {
    if ids.is_empty() || ids.len() > 100_000 {
        return Err("Choose at least one saved item to organize.".into());
    }
    let ids = ids
        .into_iter()
        .map(|id| id.trim().to_string())
        .collect::<HashSet<_>>();
    if ids.iter().any(String::is_empty) {
        return Err("One of the selected items is invalid.".into());
    }
    Ok(ids)
}

#[tauri::command]
pub fn set_item_favourite(
    id: String,
    favourite: bool,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before changing a favourite.")?;
    let payload = session.open_payload()?;
    let next_payload = payload_with_item_favourite(&payload, id.trim(), favourite)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(session.snapshot())
}

#[tauri::command]
pub fn record_item_use(id: String, state: State<'_, VaultState>) -> VaultResult<VaultSnapshot> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before recording item use.")?;
    let payload = session.open_payload()?;
    let next_payload = payload_with_recorded_item_use(&payload, id.trim())?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(session.snapshot())
}

#[tauri::command]
pub fn delete_login(id: String, state: State<'_, VaultState>) -> VaultResult<DeleteLoginResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a saved login to delete.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before deleting a login.")?;
    let payload = session.open_payload()?;
    let entry = payload
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .cloned()
        .ok_or("That saved login no longer exists.")?;
    let mut next_payload = payload_without_login(&payload, id)?;
    trash_item(&mut next_payload, TaggedItem::Login(entry));
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeleteLoginResult {
        deleted_id: id.to_string(),
        snapshot: session.snapshot(),
    })
}

#[tauri::command]
pub fn merge_duplicate_logins(
    request: MergeDuplicateLoginsRequest,
    state: State<'_, VaultState>,
) -> VaultResult<MergeDuplicateLoginsResult> {
    let keep_id = request.keep_id.trim().to_string();
    if keep_id.is_empty() {
        return Err("Choose the login you want to keep.".into());
    }
    if request.remove_ids.is_empty() {
        return Err("Choose at least one duplicate to merge.".into());
    }
    let remove_ids = request
        .remove_ids
        .into_iter()
        .map(|id| id.trim().to_string())
        .collect::<Vec<_>>();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before merging logins.")?;
    let payload = session.open_payload()?;
    let next_payload = crate::vault::storage::merged_duplicate_payload(
        &payload,
        &keep_id,
        &remove_ids,
        &request.choices,
    )?;
    let revision_backup_name = snapshot_vault_revision(&session.path, "merge")?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(MergeDuplicateLoginsResult {
        id: keep_id,
        snapshot: session.snapshot(),
        revision_backup_name,
    })
}

const MIN_COMPARED_LOGINS: usize = 2;
const MAX_COMPARED_LOGINS: usize = 16;

fn checked_comparison_ids(ids: Vec<String>) -> VaultResult<Vec<String>> {
    if ids.len() < MIN_COMPARED_LOGINS {
        return Err("Choose at least two logins to compare.".into());
    }
    if ids.len() > MAX_COMPARED_LOGINS {
        return Err(format!(
            "Choose at most {MAX_COMPARED_LOGINS} logins to compare."
        ));
    }
    let mut seen = HashSet::with_capacity(ids.len());
    let mut checked = Vec::with_capacity(ids.len());
    for id in ids {
        let id = id.trim().to_string();
        if id.is_empty() {
            return Err("One of the selected logins is invalid.".into());
        }
        if !seen.insert(id.clone()) {
            return Err("Each login can be compared only once.".into());
        }
        checked.push(id);
    }
    Ok(checked)
}

#[tauri::command]
pub fn get_merge_comparison(
    ids: Vec<String>,
    state: State<'_, VaultState>,
) -> VaultResult<MergeComparison> {
    merge_comparison_in_state(ids, &state)
}

fn merge_comparison_in_state(ids: Vec<String>, state: &VaultState) -> VaultResult<MergeComparison> {
    let ids = checked_comparison_ids(ids)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let mut opened = Vec::with_capacity(ids.len());
    for id in &ids {
        opened.push(session.open_item(id)?);
    }
    let group = opened
        .iter()
        .map(|item| match &**item {
            TaggedItem::Login(entry) => Ok(entry),
            _ => Err("One of those logins no longer exists.".to_string()),
        })
        .collect::<VaultResult<Vec<_>>>()?;
    Ok(crate::vault::snapshot::merge_comparison_for(&group))
}

#[tauri::command]
pub fn reveal_login_secret(
    id: String,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<String> {
    crate::commands::require_release_presence(&state, &presence)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(&id)?;
    let TaggedItem::Login(entry) = &*item else {
        return Err("That saved login no longer exists.".into());
    };
    Ok(entry.password.clone())
}

#[cfg(test)]
mod keep_password_tests {
    use super::*;
    use crate::vault::storage::payload_with_saved_login;
    use crate::vault::VaultEntry;

    fn stored_login() -> VaultPayload {
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
        let payload = stored_login();
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
        let payload = stored_login();
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
        let payload = stored_login();
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
        let payload = stored_login();
        let mut updated = VaultEntry::default();
        updated.id = "login-missing".to_string();
        updated.password = "fictional-new-secret".to_string();

        assert!(payload_with_saved_login(&payload, updated, None, 9001).is_err());
        assert_eq!(payload.entries[0].password, "fictional-stored-secret");
        assert_eq!(payload.entries[0].revision, 7);
        assert!(payload.history.is_empty());
    }
}

#[cfg(test)]
mod save_login_command_tests {
    use super::*;
    use crate::commands::test_support::{login_input, TestVault};

    #[test]
    fn a_typed_password_is_committed_to_the_vault_file() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");

        let result = save_login_in_state(
            login_input(
                Some("login-a"),
                "https://northwind.example",
                "fictional-new-secret",
            ),
            &vault.state,
        )
        .expect("saved login");

        assert_eq!(result.id, "login-a");
        let stored = vault.stored_login("login-a");
        assert_eq!(stored.password, "fictional-new-secret");
        assert_eq!(stored.revision, 8);
    }

    #[test]
    fn a_blank_password_edit_keeps_the_stored_password() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");

        save_login_in_state(
            login_input(Some("login-a"), "https://northwind.example", ""),
            &vault.state,
        )
        .expect("saved login");

        let stored = vault.stored_login("login-a");
        assert_eq!(stored.password, "fictional-stored-secret");
        assert_eq!(stored.password_updated_at, 42);
    }
}

#[cfg(test)]
mod add_items_tag_command_tests {
    use super::*;
    use crate::commands::test_support::TestVault;

    #[test]
    fn adding_a_tag_commits_it_to_the_selected_records() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");

        let snapshot = add_items_tag_in_state(
            vec!["login-a".to_string()],
            "  Travel  ".to_string(),
            &vault.state,
        )
        .expect("tag added");

        assert_eq!(snapshot.entries[0].tags, vec!["Travel"]);
        assert_eq!(vault.stored_login("login-a").tags, vec!["Travel"]);
    }

    #[test]
    fn an_empty_selection_or_tag_is_rejected_without_touching_the_record() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");

        assert!(add_items_tag_in_state(Vec::new(), "travel".to_string(), &vault.state).is_err());
        assert!(add_items_tag_in_state(
            vec!["login-a".to_string()],
            "   ".to_string(),
            &vault.state
        )
        .is_err());
        assert!(
            add_items_tag_in_state(vec!["login-a".to_string()], "x".repeat(51), &vault.state)
                .is_err()
        );

        let stored = vault.stored_login("login-a");
        assert!(stored.tags.is_empty());
        assert_eq!(stored.updated_at, 41);
    }
}

#[cfg(test)]
mod merge_comparison_command_tests {
    use super::*;
    use crate::commands::test_support::TestVault;
    use crate::vault::VaultEntry;

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

        let comparison = merge_comparison_in_state(ids(&["login-a", "login-b"]), &vault.state)
            .expect("comparison");

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
                merge_comparison_in_state(repeated, &vault.state).err(),
                Some("Each login can be compared only once.".to_string())
            );
        }
    }

    #[test]
    fn one_id_or_none_is_rejected() {
        let vault = vault_with_two_secret_logins();

        for few in [Vec::new(), ids(&["login-a"])] {
            assert_eq!(
                merge_comparison_in_state(few, &vault.state).err(),
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
            merge_comparison_in_state(many, &vault.state).err(),
            Some("Choose at most 16 logins to compare.".to_string())
        );
    }

    #[test]
    fn the_cap_itself_is_accepted_up_to_the_first_missing_login() {
        let vault = vault_with_two_secret_logins();
        let mut at_cap = ids(&["login-a", "login-b"]);
        at_cap.extend((2..MAX_COMPARED_LOGINS).map(|index| format!("missing-{index}")));

        let error = merge_comparison_in_state(at_cap, &vault.state).err();

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
            merge_comparison_in_state(ids(&["login-a", "   "]), &vault.state).err(),
            Some("One of the selected logins is invalid.".to_string())
        );
    }

    #[test]
    fn an_unknown_login_is_rejected() {
        let vault = vault_with_two_secret_logins();

        assert!(merge_comparison_in_state(ids(&["login-a", "missing"]), &vault.state).is_err());
    }

    #[test]
    fn a_locked_vault_is_rejected() {
        let state = VaultState::default();

        assert_eq!(
            merge_comparison_in_state(ids(&["login-a", "login-b"]), &state).err(),
            Some("Unlock your vault first.".to_string())
        );
    }
}
