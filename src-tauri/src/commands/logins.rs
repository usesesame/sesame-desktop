use std::collections::HashSet;

use tauri::State;

use crate::release::ReleasePresence;
use crate::vault::backup::snapshot_vault_revision;
use crate::vault::imports::{entry_from_input, resolved_totp};
use crate::vault::snapshot::{current_totp, login_card_for, login_summary_for};
use crate::vault::storage::{
    commit_payload_change, materialize_entry_folder, payload_with_item_favourite,
    payload_with_item_folder_id, payload_with_recorded_item_use, payload_without_login,
};
use crate::vault::trash::trash_item;
use crate::vault::{
    DeleteLoginResult, LoginInput, MergeComparison, MergeDuplicateLoginsRequest,
    MergeDuplicateLoginsResult, SaveLoginResult, TaggedItem, VaultEntry, VaultPayload, VaultResult,
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
        .iter_mut()
        .find(|saved| saved.id == entry_id)
    {
        let previous = existing.clone();
        let mut updated = entry;
        updated.created_at = if existing.created_at > 0 {
            existing.created_at
        } else {
            updated.created_at
        };
        updated.import_source = existing.import_source.clone();
        updated.legacy_fields = existing.legacy_fields.clone();
        updated.favourite = existing.favourite;
        updated.last_used_at = existing.last_used_at;
        updated.totp = resolved_totp(totp_input, previous.totp.clone());
        keep_stored_password_on_blank_edit(&mut updated, &previous);
        updated.password_updated_at =
            if previous.password == updated.password && previous.password_updated_at > 0 {
                previous.password_updated_at
            } else {
                updated.password_updated_at
            };
        updated.revision = existing.revision.saturating_add(1);
        *existing = updated;
        crate::vault::history::capture_history(&mut next_payload, TaggedItem::Login(previous));
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

fn keep_stored_password_on_blank_edit(updated: &mut VaultEntry, previous: &VaultEntry) {
    if updated.password.is_empty() {
        updated.password = previous.password.clone();
        updated.password_updated_at = previous.password_updated_at;
    }
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

#[tauri::command]
pub fn get_merge_comparison(
    ids: Vec<String>,
    state: State<'_, VaultState>,
) -> VaultResult<MergeComparison> {
    if ids.len() < 2 {
        return Err("Choose at least two logins to compare.".into());
    }
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let mut opened = Vec::with_capacity(ids.len());
    for id in &ids {
        opened.push(session.open_item(id.trim())?);
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

    #[test]
    fn a_blank_edit_keeps_the_stored_password() {
        let mut updated = VaultEntry {
            id: "login-a".to_string(),
            password: String::new(),
            ..VaultEntry::default()
        };
        let previous = VaultEntry {
            id: "login-a".to_string(),
            password: "fictional-stored-secret".to_string(),
            password_updated_at: 42,
            ..VaultEntry::default()
        };

        keep_stored_password_on_blank_edit(&mut updated, &previous);

        assert_eq!(updated.password, "fictional-stored-secret");
        assert_eq!(updated.password_updated_at, 42);
    }

    #[test]
    fn a_typed_password_replaces_the_stored_one() {
        let mut updated = VaultEntry {
            id: "login-a".to_string(),
            password: "fictional-new-secret".to_string(),
            ..VaultEntry::default()
        };
        let previous = VaultEntry {
            id: "login-a".to_string(),
            password: "fictional-stored-secret".to_string(),
            password_updated_at: 42,
            ..VaultEntry::default()
        };

        keep_stored_password_on_blank_edit(&mut updated, &previous);

        assert_eq!(updated.password, "fictional-new-secret");
    }
}
