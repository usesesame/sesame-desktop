use std::collections::HashSet;

use zeroize::Zeroizing;

use crate::application::release::require_release_presence;
use crate::release::ReleasePresence;
use crate::vault::backup::snapshot_vault_revision;
use crate::vault::imports::{entry_from_input, resolved_totp};
use crate::vault::snapshot::{
    current_totp, duplicate_groups_from_summaries, login_summary_for, merge_comparison_for,
};
use crate::vault::storage::{
    commit_payload_change, create_folder_in_payload, delete_folder_from_payload,
    materialize_entry_folder, merged_duplicate_payload, payload_with_added_item_tag,
    payload_with_item_favourite, payload_with_item_folder_id, payload_with_login_folders,
    payload_with_recorded_item_use, payload_with_saved_login, payload_without_login,
    rename_folder_in_payload,
};
use crate::vault::trash::trash_item;
use crate::vault::util::unix_timestamp;
use crate::vault::{
    DeleteLoginResult, DuplicateGroup, LoginInput, MergeComparison, MergeDuplicateLoginsRequest,
    MergeDuplicateLoginsResult, SaveLoginResult, TaggedItem, TotpCodeEntry, TotpRefresh,
    VaultPayload, VaultResult, VaultSnapshot, VaultState,
};

pub(crate) fn save_login_in_state(
    state: &VaultState,
    input: LoginInput,
) -> VaultResult<SaveLoginResult> {
    let totp_input = input.totp.clone();
    let keep_backup_codes = input.keep_backup_codes;
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
        if keep_backup_codes && updated.backup_codes.is_empty() {
            updated.backup_codes = previous.backup_codes.clone();
        }
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

pub(crate) fn delete_login_in_state(
    state: &VaultState,
    id: &str,
) -> VaultResult<DeleteLoginResult> {
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

pub(crate) fn reveal_login_secret_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    id: &str,
) -> VaultResult<Zeroizing<String>> {
    require_release_presence(state, presence)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(id)?;
    let TaggedItem::Login(entry) = &*item else {
        return Err("That saved login no longer exists.".into());
    };
    Ok(Zeroizing::new(entry.password.clone()))
}

/// Folder names resolve to a stable ID before the payload is committed.
pub(crate) fn set_login_folders_in_state(
    state: &VaultState,
    ids: Vec<String>,
    folder: &str,
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
    let next_payload = payload_with_login_folders(&payload, &ids, folder)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(session.snapshot())
}

pub(crate) fn bulk_assign_folder_in_state(
    state: &VaultState,
    ids: Vec<String>,
    folder_id: Option<&str>,
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
    let next_payload = payload_with_item_folder_id(&payload, &ids, folder_id)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(session.snapshot())
}

pub(crate) fn add_items_tag_in_state(
    state: &VaultState,
    ids: Vec<String>,
    tag: &str,
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
    let next_payload = payload_with_added_item_tag(&payload, &ids, tag)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(session.snapshot())
}

pub(crate) fn create_folder_in_state(state: &VaultState, name: &str) -> VaultResult<VaultSnapshot> {
    change_folders_in_state(state, |payload| create_folder_in_payload(payload, name))
}

pub(crate) fn rename_folder_in_state(
    state: &VaultState,
    folder_id: &str,
    name: &str,
) -> VaultResult<VaultSnapshot> {
    change_folders_in_state(state, |payload| {
        rename_folder_in_payload(payload, folder_id.trim(), name)
    })
}

pub(crate) fn delete_folder_in_state(
    state: &VaultState,
    folder_id: &str,
) -> VaultResult<VaultSnapshot> {
    change_folders_in_state(state, |payload| {
        delete_folder_from_payload(payload, folder_id.trim())
    })
}

fn change_folders_in_state(
    state: &VaultState,
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

pub(crate) fn set_item_favourite_in_state(
    state: &VaultState,
    id: &str,
    favourite: bool,
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

pub(crate) fn record_item_use_in_state(state: &VaultState, id: &str) -> VaultResult<VaultSnapshot> {
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

pub(crate) fn duplicate_groups_in_state(state: &VaultState) -> VaultResult<Vec<DuplicateGroup>> {
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
    Ok(duplicate_groups_from_summaries(summaries))
}

/// Every saved code at once, for the authenticator view. Requires an unlocked
/// vault, and returns derived codes only so the seed never crosses the boundary.
pub(crate) fn totp_codes_in_state(state: &VaultState) -> VaultResult<Vec<TotpCodeEntry>> {
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
        codes.push(TotpCodeEntry {
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

pub(crate) fn refresh_totp_in_state(state: &VaultState, id: &str) -> VaultResult<TotpRefresh> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(id)?;
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
    Ok(TotpRefresh {
        totp_code,
        totp_remaining,
    })
}

pub(crate) fn merge_duplicate_logins_in_state(
    state: &VaultState,
    request: MergeDuplicateLoginsRequest,
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
    let next_payload = merged_duplicate_payload(&payload, &keep_id, &remove_ids, &request.choices)?;
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
pub(super) const MAX_COMPARED_LOGINS: usize = 16;

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

pub(crate) fn merge_comparison_in_state(
    state: &VaultState,
    ids: Vec<String>,
) -> VaultResult<MergeComparison> {
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
    Ok(merge_comparison_for(&group))
}
