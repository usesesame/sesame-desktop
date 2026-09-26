use tauri::{AppHandle, State};

use crate::browser_fill::SaveKind;
use crate::vault::imports::entry_from_input;
use crate::vault::storage::{commit_payload_change, payload_with_saved_login};
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
        password: payload.password.to_string(),
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
    let current = session.open_payload()?;
    let mut next_payload = current.clone();
    next_payload.entries.push(entry);
    commit_payload_change(session, next_payload)?;
    vault.advance_session_epoch();
    Ok(SaveLoginResult {
        id: entry_id,
        snapshot: session.snapshot(),
    })
}

/// Changes only the password; the outgoing value is captured to history first.
fn save_login_update(
    vault: &VaultState,
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
    let current = session.open_payload()?;
    if !browser_fill::verify_update_target(&current.entries, &payload.origin, &target_id) {
        return Err("That saved login no longer matches this site.".to_string());
    }

    let updated = current
        .entries
        .iter()
        .find(|entry| entry.id == target_id)
        .cloned()
        .ok_or("That saved login no longer exists.")?;
    let next_payload = payload_with_saved_login(
        &current,
        updated,
        Some(payload.password.to_string()),
        unix_timestamp(),
    )?;
    commit_payload_change(session, next_payload)?;
    vault.advance_session_epoch();
    Ok(SaveLoginResult {
        id: target_id,
        snapshot: session.snapshot(),
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

#[cfg(test)]
mod browser_update_tests {
    use super::save_login_update;
    use crate::browser_fill::{self, SaveKind};
    use crate::commands::test_support::TestVault;
    use crate::vault::storage::payload_with_saved_login;
    use crate::vault::{VaultEntry, VaultPayload};

    fn payload_with_stored_login() -> VaultPayload {
        let mut payload = VaultPayload::default();
        payload.entries.push(VaultEntry {
            id: "login-a".to_string(),
            password: "fictional-stored-secret".to_string(),
            updated_at: 41,
            password_updated_at: 40,
            revision: 7,
            ..VaultEntry::default()
        });
        payload
    }

    #[test]
    fn an_approved_update_stamps_both_timestamps_and_bumps_the_revision() {
        let payload = payload_with_stored_login();
        let updated = payload.entries[0].clone();

        let next = payload_with_saved_login(
            &payload,
            updated,
            Some("fictional-new-secret".to_string()),
            9001,
        )
        .expect("saved update");

        assert_eq!(next.entries[0].password, "fictional-new-secret");
        assert_eq!(next.entries[0].updated_at, 9001);
        assert_eq!(next.entries[0].password_updated_at, 9001);
        assert_eq!(next.entries[0].revision, 8);
        assert_eq!(next.history.len(), 1);
    }

    #[test]
    fn an_approved_update_never_keeps_the_retired_password_in_the_login() {
        let payload = payload_with_stored_login();
        let updated = payload.entries[0].clone();

        let next = payload_with_saved_login(
            &payload,
            updated,
            Some("fictional-new-secret".to_string()),
            9001,
        )
        .expect("saved update");

        assert!(!next.entries[0].password.contains("fictional-stored-secret"));
        assert_eq!(next.history.len(), 1);
    }

    #[test]
    fn an_approved_update_commits_the_new_password_through_the_command() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");
        let payload = browser_fill::SavePayload {
            kind: SaveKind::Update,
            title: "Northwind".to_string(),
            username: "fictional-user".to_string(),
            password: zeroize::Zeroizing::new("fictional-new-secret".to_string()),
            origin: "https://northwind.example".to_string(),
            epoch: vault.state.session_epoch(),
            candidates: vec![browser_fill::test_update_candidate(
                "login-a",
                "https://northwind.example",
            )],
        };

        let result = save_login_update(&vault.state, payload, Some("login-a".to_string()))
            .expect("saved update");

        assert_eq!(result.id, "login-a");
        let stored = vault.stored_login("login-a");
        assert_eq!(stored.password, "fictional-new-secret");
        assert_ne!(stored.password_updated_at, 42);
        assert_eq!(stored.revision, 8);
    }
}
