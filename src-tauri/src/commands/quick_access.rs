use serde::Serialize;
use tauri::{AppHandle, State, WebviewWindow};

use crate::vault::snapshot::current_totp;
use crate::vault::storage::vault_path;
use crate::vault::util::{domain_from_url, initials_for};
use crate::vault::{VaultEntry, VaultPayload, VaultResult, VaultState};

const QUICK_ACCESS_WINDOW: &str = "quick-access";
const QUICK_ACCESS_RESULT_LIMIT: usize = 6;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickAccessStatus {
    exists: bool,
    unlocked: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuickAccessEntry {
    id: String,
    title: String,
    site: String,
    initials: String,
    has_totp: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuickAccessSecret {
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp_code: Option<String>,
}

fn require_quick_access(window: &WebviewWindow) -> VaultResult<()> {
    if window.label() == QUICK_ACCESS_WINDOW {
        Ok(())
    } else {
        Err("That command is available only from quick access.".into())
    }
}

#[tauri::command]
pub fn get_quick_access_status(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, VaultState>,
) -> VaultResult<QuickAccessStatus> {
    require_quick_access(&window)?;
    let unlocked = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault state.".to_string())?
        .is_some();
    Ok(QuickAccessStatus {
        exists: vault_path(&app)?.exists(),
        unlocked,
    })
}

#[tauri::command]
pub fn search_quick_access_entries(
    window: WebviewWindow,
    state: State<'_, VaultState>,
    query: String,
) -> VaultResult<Vec<QuickAccessEntry>> {
    require_quick_access(&window)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_ref()
        .ok_or("Unlock your vault in Sesame first.")?;
    Ok(quick_access_entries(&session.payload, &query))
}

#[tauri::command]
pub fn get_quick_access_secret(
    window: WebviewWindow,
    state: State<'_, VaultState>,
    id: String,
) -> VaultResult<QuickAccessSecret> {
    require_quick_access(&window)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_ref()
        .ok_or("Unlock your vault in Sesame first.")?;
    let entry = session
        .payload
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .ok_or("That saved login no longer exists.")?;
    Ok(quick_access_secret(entry))
}

fn quick_access_entries(payload: &VaultPayload, query: &str) -> Vec<QuickAccessEntry> {
    let needle = query.trim().to_lowercase();
    payload
        .entries
        .iter()
        .filter(|entry| quick_access_matches(entry, &needle))
        .take(QUICK_ACCESS_RESULT_LIMIT)
        .map(|entry| QuickAccessEntry {
            id: entry.id.clone(),
            title: entry.title.clone(),
            site: domain_from_url(&entry.url),
            initials: initials_for(&entry.title),
            has_totp: entry.totp.is_some(),
        })
        .collect()
}

fn quick_access_matches(entry: &VaultEntry, needle: &str) -> bool {
    needle.is_empty()
        || [
            entry.title.as_str(),
            entry.username.as_str(),
            entry.email.as_str(),
            entry.url.as_str(),
        ]
        .iter()
        .any(|field| field.to_lowercase().contains(needle))
}

fn quick_access_secret(entry: &VaultEntry) -> QuickAccessSecret {
    QuickAccessSecret {
        password: entry.password.clone(),
        totp_code: entry
            .totp
            .as_deref()
            .and_then(current_totp)
            .map(|(code, remaining, _)| (code, remaining))
            .map(|(code, _)| code),
    }
}
