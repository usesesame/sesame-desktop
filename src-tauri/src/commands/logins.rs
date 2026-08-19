use std::collections::HashSet;

use tauri::State;

use crate::vault::backup::snapshot_vault_revision;
use crate::vault::imports::entry_from_input;
use crate::vault::snapshot::{
    current_totp, folder_name_for, login_card_for, login_summary_for, snapshot_for,
};
use crate::vault::storage::{
    commit_payload_change, materialize_entry_folder, payload_with_favourite,
    payload_with_login_folder_id, payload_with_recorded_use, payload_without_login,
};
use crate::vault::trash::trash_item;
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
    Ok(snapshot_for(&session.payload))
}

/// Matched in Rust because the snapshot deliberately omits usernames; only ids cross back.
#[tauri::command]
pub fn search_entries(query: String, state: State<'_, VaultState>) -> VaultResult<Vec<String>> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Ok(Vec::new());
    }
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let payload = &session.payload;
    Ok(payload
        .entries
        .iter()
        .filter(|entry| entry_matches_search(payload, entry, &needle))
        .map(|entry| entry.id.clone())
        .collect())
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
    Ok(suggested_values(&session.payload, &field))
}

fn suggested_values(payload: &VaultPayload, field: &str) -> Vec<String> {
    let values: Box<dyn Iterator<Item = &str>> = match field {
        "username" => Box::new(payload.entries.iter().map(|entry| entry.username.as_str())),
        "email" => Box::new(
            payload
                .entries
                .iter()
                .map(|entry| entry.email.as_str())
                .chain(
                    payload
                        .identities
                        .iter()
                        .map(|identity| identity.email.as_str()),
                ),
        ),
        // An unknown field must not fall back to another field's values.
        _ => return Vec::new(),
    };
    let mut seen = HashSet::new();
    let mut suggestions = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() || !seen.insert(trimmed) {
            continue;
        }
        suggestions.push(trimmed.to_string());
        if suggestions.len() >= MAX_SUGGESTIONS {
            break;
        }
    }
    suggestions
}

fn entry_matches_search(
    payload: &VaultPayload,
    entry: &crate::vault::VaultEntry,
    needle: &str,
) -> bool {
    [
        entry.title.as_str(),
        entry.username.as_str(),
        entry.email.as_str(),
        entry.url.as_str(),
    ]
    .iter()
    .any(|field| field.to_lowercase().contains(needle))
        || folder_name_for(payload, entry)
            .to_lowercase()
            .contains(needle)
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
    let entry = session
        .payload
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .ok_or("That saved login no longer exists.")?;
    Ok(login_card_for(&session.payload, entry))
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
    let entry = session
        .payload
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .ok_or("That saved login no longer exists.")?;
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
    Ok(crate::vault::snapshot::duplicate_groups_for(
        &session.payload,
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
    let mut codes = Vec::new();
    for entry in &session.payload.entries {
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
    codes.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
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
    let entry = session
        .payload
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .ok_or("That saved login no longer exists.")?;
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
    let mut entry = entry_from_input(input)?;
    let entry_id = entry.id.clone();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a login.")?;
    let mut next_payload = session.payload.clone();
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
        snapshot: snapshot_for(&session.payload),
    })
}

/// Folder names resolve to a stable ID before the payload is committed.
#[tauri::command]
pub fn set_login_folders(
    ids: Vec<String>,
    folder: String,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    let ids = checked_login_ids(ids)?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before organizing logins.")?;
    let next_payload =
        crate::vault::storage::payload_with_login_folders(&session.payload, &ids, &folder)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(snapshot_for(&session.payload))
}

#[tauri::command]
pub fn bulk_assign_folder(
    ids: Vec<String>,
    folder_id: Option<String>,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    let ids = checked_login_ids(ids)?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before organizing logins.")?;
    let next_payload = payload_with_login_folder_id(&session.payload, &ids, folder_id.as_deref())?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(snapshot_for(&session.payload))
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
    let next_payload = change(&session.payload)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(snapshot_for(&session.payload))
}

fn checked_login_ids(ids: Vec<String>) -> VaultResult<HashSet<String>> {
    if ids.is_empty() || ids.len() > 100_000 {
        return Err("Choose at least one saved login to organize.".into());
    }
    let ids = ids
        .into_iter()
        .map(|id| id.trim().to_string())
        .collect::<HashSet<_>>();
    if ids.iter().any(String::is_empty) {
        return Err("One of the selected logins is invalid.".into());
    }
    Ok(ids)
}

#[tauri::command]
pub fn set_login_favourite(
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
    let next_payload = payload_with_favourite(&session.payload, id.trim(), favourite)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(snapshot_for(&session.payload))
}

#[tauri::command]
pub fn record_login_use(id: String, state: State<'_, VaultState>) -> VaultResult<VaultSnapshot> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before recording login use.")?;
    let next_payload = payload_with_recorded_use(&session.payload, id.trim())?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(snapshot_for(&session.payload))
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
    let entry = session
        .payload
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .cloned()
        .ok_or("That saved login no longer exists.")?;
    let mut next_payload = payload_without_login(&session.payload, id)?;
    trash_item(&mut next_payload, TaggedItem::Login(entry));
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeleteLoginResult {
        deleted_id: id.to_string(),
        snapshot: snapshot_for(&session.payload),
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
    let next_payload = crate::vault::storage::merged_duplicate_payload(
        &session.payload,
        &keep_id,
        &remove_ids,
        &request.choices,
    )?;
    let revision_backup_name = snapshot_vault_revision(&session.path, "merge")?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(MergeDuplicateLoginsResult {
        id: keep_id,
        snapshot: snapshot_for(&session.payload),
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
    let mut group = Vec::with_capacity(ids.len());
    for id in &ids {
        let entry = session
            .payload
            .entries
            .iter()
            .find(|entry| entry.id == id.trim())
            .ok_or("One of those logins no longer exists.")?;
        group.push(entry);
    }
    Ok(crate::vault::snapshot::merge_comparison_for(&group))
}
