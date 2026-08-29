use tauri::{AppHandle, State};

use crate::browser_fill::SaveKind;
use crate::vault::imports::entry_from_input;
use crate::vault::snapshot::snapshot_for;
use crate::vault::storage::commit_payload_change;
use crate::vault::types::TaggedItem;
use crate::vault::util::unix_timestamp;
use crate::vault::{LoginInput, SaveLoginResult, VaultResult, VaultState};
use crate::{browser_fill, browser_host, diagnostics};

#[tauri::command]
pub fn record_diagnostic(app: AppHandle, input: diagnostics::DiagnosticInput) -> VaultResult<()> {
    diagnostics::record(&app, input)
}

#[tauri::command]
pub fn get_diagnostic_status(app: AppHandle) -> VaultResult<diagnostics::DiagnosticStatus> {
    diagnostics::status(&app)
}

#[tauri::command]
pub fn export_diagnostics(app: AppHandle, destination: String) -> VaultResult<String> {
    diagnostics::export(&app, &destination)
}

#[tauri::command]
pub fn clear_diagnostics(app: AppHandle) -> VaultResult<()> {
    diagnostics::clear(&app)
}

#[tauri::command]
pub fn get_browser_integration_status() -> VaultResult<browser_host::BrowserIntegrationStatus> {
    Ok(browser_host::status())
}

#[tauri::command]
pub fn repair_browser_integration(
    app: AppHandle,
) -> VaultResult<browser_host::BrowserIntegrationStatus> {
    match browser_host::repair() {
        Ok(status) => {
            diagnostics::record_browser_host_registration(&app, "registration_ok");
            Ok(status)
        }
        Err(error) => {
            diagnostics::record_browser_host_registration(&app, error.diagnostic_code());
            Err(error.message().to_string())
        }
    }
}

#[tauri::command]
pub fn resolve_browser_fill(
    app: AppHandle,
    state: State<'_, browser_fill::BrowserFillState>,
    approval_id: String,
    login_id: Option<String>,
    remember: bool,
) -> VaultResult<()> {
    browser_fill::resolve(&app, state, approval_id, login_id, remember)
}

#[tauri::command]
pub fn get_pending_browser_fill(
    state: State<'_, browser_fill::BrowserFillState>,
) -> Option<browser_fill::BrowserFillRequestEvent> {
    browser_fill::pending(state)
}

/// `update` changes only the password of a broker-found candidate; the caller can never name a login outside that set.
#[tauri::command]
pub fn resolve_browser_save(
    app: AppHandle,
    state: State<'_, browser_fill::BrowserFillState>,
    vault: State<'_, VaultState>,
    approval_id: String,
    approved: bool,
    selected_id: Option<String>,
) -> VaultResult<Option<SaveLoginResult>> {
    if !approved {
        browser_fill::resolve_save(&app, &state, &approval_id, false)?;
        return Ok(None);
    }

    let payload = browser_fill::save_payload(&state, &approval_id)
        .ok_or("That browser approval expired or is no longer available.")?;

    let save_result = match payload.kind {
        SaveKind::New => save_new_login(&vault, payload),
        SaveKind::Update => save_login_update(&vault, payload, selected_id),
    };

    match save_result {
        Ok(result) => {
            browser_fill::resolve_save(&app, &state, &approval_id, true)?;
            Ok(Some(result))
        }
        Err(error) => {
            // Release the broker so the extension is not left waiting.
            let _ = browser_fill::resolve_save(&app, &state, &approval_id, false);
            Err(error)
        }
    }
}

fn save_new_login(
    vault: &State<'_, VaultState>,
    payload: browser_fill::SavePayload,
) -> VaultResult<SaveLoginResult> {
    let input = LoginInput {
        urls: Vec::new(),
        tags: Vec::new(),
        id: None,
        title: payload.title,
        url: payload.origin,
        username: payload.username,
        email: String::new(),
        password: payload.password,
        folder: String::new(),
        folder_id: None,
        totp: None,
        backup_codes: Vec::new(),
        recovery_email: String::new(),
        recovery_phone: String::new(),
        recovery_not_applicable: false,
        notes: String::new(),
    };
    let entry = entry_from_input(input)?;
    let entry_id = entry.id.clone();
    let mut session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a login.".to_string())?;
    if vault.session_epoch() != payload.epoch {
        return Err(
            "The vault changed while this approval was open. Ask the browser to save again."
                .to_string(),
        );
    }
    let mut next_payload = session.payload.clone();
    next_payload.entries.push(entry);
    commit_payload_change(session, next_payload)?;
    vault.advance_session_epoch();
    Ok(SaveLoginResult {
        id: entry_id,
        snapshot: snapshot_for(&session.payload),
    })
}

/// Changes only the password; the outgoing value is captured to history first.
fn save_login_update(
    vault: &State<'_, VaultState>,
    payload: browser_fill::SavePayload,
    selected_id: Option<String>,
) -> VaultResult<SaveLoginResult> {
    let target_id = selected_id
        .filter(|id| {
            payload
                .candidates
                .iter()
                .any(|candidate| candidate.id == *id)
        })
        .ok_or_else(|| {
            "Choose which saved login this update belongs to before confirming.".to_string()
        })?;

    let mut session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a login.".to_string())?;
    if vault.session_epoch() != payload.epoch {
        return Err(
            "The vault changed while this approval was open. Ask the browser to save again."
                .to_string(),
        );
    }
    // Re-verified under the lock: still exactly this origin's saved login.
    if !browser_fill::verify_update_target(&session.payload.entries, &payload.origin, &target_id) {
        return Err("That saved login no longer matches this site.".to_string());
    }

    let mut next_payload = session.payload.clone();
    let Some(existing) = next_payload
        .entries
        .iter_mut()
        .find(|entry| entry.id == target_id)
    else {
        return Err("That saved login no longer exists.".to_string());
    };
    let previous = existing.clone();
    existing.password = payload.password;
    existing.updated_at = unix_timestamp();
    existing.revision = existing.revision.saturating_add(1);
    crate::vault::history::capture_history(&mut next_payload, TaggedItem::Login(previous));
    commit_payload_change(session, next_payload)?;
    vault.advance_session_epoch();
    Ok(SaveLoginResult {
        id: target_id,
        snapshot: snapshot_for(&session.payload),
    })
}

#[tauri::command]
pub fn get_pending_browser_save(
    state: State<'_, browser_fill::BrowserFillState>,
) -> Option<browser_fill::BrowserSaveRequestEvent> {
    browser_fill::pending_save(state)
}

#[tauri::command]
pub fn resolve_browser_identity_fill(
    app: AppHandle,
    state: State<'_, browser_fill::BrowserFillState>,
    approval_id: String,
    identity_id: Option<String>,
) -> VaultResult<()> {
    browser_fill::resolve_identity(&app, state, approval_id, identity_id)
}

#[tauri::command]
pub fn get_pending_browser_identity_fill(
    state: State<'_, browser_fill::BrowserFillState>,
) -> Option<browser_fill::BrowserIdentityRequestEvent> {
    browser_fill::pending_identity(state)
}

#[tauri::command]
pub fn resolve_browser_card_fill(
    app: AppHandle,
    state: State<'_, browser_fill::BrowserFillState>,
    approval_id: String,
    card_id: Option<String>,
) -> VaultResult<()> {
    browser_fill::resolve_card(&app, state, approval_id, card_id)
}

#[tauri::command]
pub fn get_pending_browser_card_fill(
    state: State<'_, browser_fill::BrowserFillState>,
) -> Option<browser_fill::BrowserCardRequestEvent> {
    browser_fill::pending_card(state)
}
