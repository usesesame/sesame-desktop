use std::path::PathBuf;

use serde::Serialize;
use tauri::AppHandle;

use crate::sync::canonical::{ProofError, ProofKind};
use crate::sync::checkpoint::Checkpoint;
use crate::sync::client::{StateView, SyncClient, SyncError};
use crate::sync::devicelist::DeviceList;
use crate::sync::engine::{
    check_peer_checkpoints, create_entry, oldest_revision_to_compare, open_label, seal_label,
    verify_server_view, PeerView, ServedCheckpoint, ServerView, VerifiedUpdate,
};
use crate::sync::header::{verify_header_chain, Header};
use crate::sync::identity::DeviceIdentity;
use crate::sync::state::SyncState;
use crate::vault::{VaultResult, VaultState};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncDeviceView {
    pub device_id: String,
    pub label: String,
    pub state: String,
    pub is_this_device: bool,
    pub added_index: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusView {
    pub enrolled: bool,
    pub state: String,
    pub vault_epoch: u64,
    pub revision: u64,
    pub devices: Vec<SyncDeviceView>,
    pub needs_new_key: bool,
    pub alarm: Option<String>,
    pub confirmed_at: Option<u64>,
}

pub(super) fn local_data_dir(app: &AppHandle) -> VaultResult<PathBuf> {
    use tauri::Manager;
    app.path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())
}

pub(super) fn present(error: SyncError) -> String {
    match error {
        SyncError::NotEntitled => format!("sync_not_entitled:{}", SyncError::NotEntitled),
        SyncError::Conflict => "sync_conflict:0".to_string(),
        other => other.to_string(),
    }
}

pub(super) fn present_proof(error: ProofError) -> String {
    match error.kind {
        ProofKind::Invalid => error.to_string(),
        ProofKind::DeviceList | ProofKind::History => format!("sync_fork:{error}"),
    }
}

pub(super) fn identity_file(app: &AppHandle) -> VaultResult<PathBuf> {
    Ok(crate::sync::identity::identity_path(&local_data_dir(app)?))
}

pub(super) fn this_identity(app: &AppHandle) -> VaultResult<DeviceIdentity> {
    DeviceIdentity::load(&identity_file(app)?)
        .map_err(|_| "Set up Sesame Sync on this device first.".to_string())
}

pub(super) fn state_file(app: &AppHandle) -> VaultResult<PathBuf> {
    Ok(crate::sync::state::state_path(&local_data_dir(app)?))
}

pub(super) fn load_state(app: &AppHandle) -> VaultResult<Option<SyncState>> {
    let state = load_join_state(app)?;
    if let Some(state) = &state {
        state.require_join_complete()?;
    }
    Ok(state)
}

pub(super) fn load_join_state(app: &AppHandle) -> VaultResult<Option<SyncState>> {
    Ok(crate::sync::state::read_protected(&state_file(app)?))
}

pub(super) fn save_state(app: &AppHandle, state: &SyncState) -> VaultResult<()> {
    crate::sync::state::write_protected(&state_file(app)?, state)
}

pub(super) fn forget_everything(app: &AppHandle) -> VaultResult<()> {
    crate::sync::identity::forget(&identity_file(app)?)?;
    crate::sync::state::forget_protected(&state_file(app)?)
}

pub(super) struct Refreshed {
    pub server: StateView,
    pub update: VerifiedUpdate,
    pub confirmed_at: Option<u64>,
}

pub(super) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

async fn history_for_peers(
    client: &SyncClient,
    update: &VerifiedUpdate,
    own_device_id: &str,
    checkpoints: &[ServedCheckpoint],
) -> Result<Vec<Header>, String> {
    let Some(oldest) = oldest_revision_to_compare(update.head.as_ref(), own_device_id, checkpoints)
    else {
        return Ok(Vec::new());
    };
    let Ok(served) = client.headers(oldest.saturating_sub(1)).await else {
        return Ok(Vec::new());
    };
    let plain: Vec<Header> = served.into_iter().map(|item| item.header).collect();
    verify_header_chain(&update.list, None, &plain).map_err(present_proof)?;
    let reaches_head = match (plain.last(), update.head.as_ref()) {
        (Some(last), Some(head)) => last.digest() == head.digest(),
        _ => false,
    };
    Ok(if reaches_head { plain } else { Vec::new() })
}

pub(super) async fn refresh(client: &SyncClient, state: &SyncState) -> Result<Refreshed, String> {
    let peer_checkpoints = client.checkpoints().await.ok();
    let server = client.state().await.map_err(present)?;
    if server.vault_id != state.vault_id {
        return Err("This device is set up for a different synced vault.".into());
    }
    let known = u64::try_from(state.entries.len())
        .map_err(|_| "The stored device list is too long.".to_string())?;
    let entries_after = client.device_list(known).await.map_err(present)?;
    let after = match &state.head {
        Some(head) => head.revision.saturating_sub(1),
        None => server.current_revision.saturating_sub(1),
    };
    let headers = if server.current_revision == 0 {
        Vec::new()
    } else {
        client.headers(after).await.map_err(present)?
    };
    let update = verify_server_view(
        state,
        client.instance_key(),
        &ServerView {
            entries_after: &entries_after,
            headers: &headers,
            latest_revision: server.current_revision,
        },
    )
    .map_err(present_proof)?;
    let confirmed_at = match peer_checkpoints {
        Some(checkpoints) if !checkpoints.is_empty() => {
            let history =
                history_for_peers(client, &update, &state.device_id, &checkpoints).await?;
            check_peer_checkpoints(
                &update.list,
                update.head.as_ref(),
                &state.device_id,
                &PeerView {
                    checkpoints: &checkpoints,
                    history: &history,
                },
                unix_now(),
            )
            .map_err(present_proof)?
        }
        _ => None,
    };
    Ok(Refreshed {
        server,
        update,
        confirmed_at,
    })
}

pub(super) async fn record_checkpoint_if_due(
    app: &AppHandle,
    client: &SyncClient,
    local: &SyncState,
    refreshed: &Refreshed,
) {
    if refreshed.server.device_state != "approved"
        || refreshed.server.activated_epoch != refreshed.server.vault_epoch
    {
        return;
    }
    let list = &refreshed.update.list;
    let head = refreshed.update.head.as_ref();
    let now = unix_now();
    let revision = head.map_or(0, |header| header.revision);
    if !crate::sync::state::checkpoint_due(
        local.last_checkpoint.as_ref(),
        list.head(),
        revision,
        now,
    ) {
        return;
    }
    let Ok(identity) = this_identity(app) else {
        return;
    };
    let checkpoint =
        identity.sign_checkpoint(Checkpoint::observe(list, head, &local.device_id, now));
    if client
        .post_checkpoint(&identity, &checkpoint)
        .await
        .is_err()
    {
        return;
    }
    let mut next = local.clone();
    next.entries = refreshed.update.entries.clone();
    next.last_checkpoint = Some(crate::sync::state::PostedCheckpoint {
        device_list_index: checkpoint.device_list_index,
        header_revision: checkpoint.header_revision,
        at: now,
    });
    let _ = save_state(app, &next);
}

pub(super) fn vault_id_of(vault: &crate::vault::UnlockedVault) -> Result<String, String> {
    let payload = vault.open_payload()?;
    payload.vault_id.clone().ok_or_else(|| {
        "This vault has no identity yet. Lock and unlock it once, then try again.".to_string()
    })
}

fn clean_label(label: &str) -> Result<String, String> {
    let label = label.trim().to_string();
    if label.is_empty() || label.chars().count() > crate::sync::engine::MAX_LABEL_CHARS {
        return Err("Give this device a name of 1 to 64 characters.".into());
    }
    Ok(label)
}

fn views_from(
    list: &DeviceList,
    state: &SyncState,
    vault_key: Option<&[u8; 32]>,
) -> Vec<SyncDeviceView> {
    let mut devices: Vec<SyncDeviceView> = list
        .all_members()
        .into_iter()
        .map(|member| {
            let label = vault_key
                .and_then(|key| {
                    open_label(
                        key,
                        &state.vault_id,
                        &member.device_id,
                        &member.sealed_label,
                    )
                })
                .unwrap_or_else(|| "A device".to_string());
            SyncDeviceView {
                device_id: member.device_id.clone(),
                label,
                state: if member.removed_index == 0 {
                    "approved".to_string()
                } else {
                    "removed".to_string()
                },
                is_this_device: member.device_id == state.device_id,
                added_index: member.added_index,
            }
        })
        .collect();
    devices.sort_by_key(|device| device.added_index);
    devices
}

fn status(state: &str) -> SyncStatusView {
    SyncStatusView {
        enrolled: false,
        state: state.to_string(),
        vault_epoch: 0,
        revision: 0,
        devices: Vec::new(),
        needs_new_key: false,
        alarm: None,
        confirmed_at: None,
    }
}

async fn initial_status(
    client: &SyncClient,
    identity_present: bool,
) -> Result<SyncStatusView, String> {
    match client.state().await {
        Ok(server) => {
            let mut view = status(if identity_present {
                "pairing"
            } else {
                "not_enrolled"
            });
            view.vault_epoch = server.vault_epoch;
            Ok(view)
        }
        Err(SyncError::NotApproved) => Ok(status("not_enrolled")),
        Err(SyncError::NotFound) => Ok(status("no_vault")),
        Err(other) => Err(present(other)),
    }
}

pub(super) fn never_turned_on(has_state: bool, has_identity: bool) -> bool {
    !has_state && !has_identity
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncLocalStatusView {
    pub state: String,
    pub revision: u64,
    pub unsynced: bool,
}

pub(super) fn local_status_for(
    state: Option<&SyncState>,
    has_identity: bool,
    unsynced: bool,
) -> SyncLocalStatusView {
    match state {
        Some(state) => SyncLocalStatusView {
            state: "approved".to_string(),
            revision: state.head_revision(),
            unsynced,
        },
        None if has_identity => SyncLocalStatusView {
            state: "pairing".to_string(),
            revision: 0,
            unsynced: false,
        },
        None => SyncLocalStatusView {
            state: "not_enrolled".to_string(),
            revision: 0,
            unsynced: false,
        },
    }
}

#[tauri::command]
pub async fn sync_local_status(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
) -> Result<SyncLocalStatusView, String> {
    let local = load_state(&app)?;
    let identity_present = identity_file(&app)?.exists();
    let unsynced = match &local {
        Some(state) => {
            let session = vault
                .session
                .lock()
                .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
            session
                .as_ref()
                .and_then(|unlocked| super::sync_transfer::local_payload_bytes(unlocked).ok())
                .is_some_and(|(plaintext, _)| state.has_local_changes(&plaintext))
        }
        None => false,
    };
    Ok(local_status_for(local.as_ref(), identity_present, unsynced))
}

#[tauri::command]
pub async fn sync_status(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
) -> Result<SyncStatusView, String> {
    let local = load_join_state(&app)?;
    let identity_present = identity_file(&app)?.exists();
    if never_turned_on(local.is_some(), identity_present) {
        return Ok(status("not_enrolled"));
    }
    let client = SyncClient::connect(&app).await?;
    let Some(local) = local else {
        return initial_status(&client, identity_present).await;
    };
    let server = match client.state().await {
        Ok(server) => server,
        Err(SyncError::NotFound) => {
            let mut view = status("no_vault");
            view.enrolled = true;
            view.alarm = Some(
                "The service no longer has this vault. It was reset and your local vault is untouched."
                    .to_string(),
            );
            return Ok(view);
        }
        Err(other) => return Err(present(other)),
    };
    if local.pending_join.is_some() {
        let mut view = status("joining");
        view.vault_epoch = server.vault_epoch;
        return Ok(view);
    }
    let mut view = status("approved");
    view.enrolled = true;
    view.vault_epoch = server.vault_epoch;
    view.revision = server.current_revision;
    let (list, state) = match refresh(&client, &local).await {
        Ok(refreshed) => {
            view.confirmed_at = refreshed.confirmed_at;
            let mut next = local.clone();
            next.entries = refreshed.update.entries.clone();
            if next.entries != local.entries {
                save_state(&app, &next)?;
            }
            (refreshed.update.list, next)
        }
        Err(message) => {
            let list = local.list().map_err(present_proof)?;
            view.alarm = Some(message.trim_start_matches("sync_fork:").to_string());
            (list, local.clone())
        }
    };
    view.devices = {
        let session = vault
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        match session.as_ref() {
            Some(unlocked) => {
                unlocked.expose_vault_key(|key| Ok(views_from(&list, &state, Some(key))))?
            }
            None => views_from(&list, &state, None),
        }
    };
    let this_device = list.member(&state.device_id);
    if this_device.is_none_or(|member| member.removed_index != 0)
        || server.device_state != "approved"
    {
        view.state = "removed".to_string();
    }
    view.needs_new_key =
        server.device_state == "approved" && server.activated_epoch < server.vault_epoch;
    Ok(view)
}

#[tauri::command]
pub async fn sync_create_vault(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
    label: String,
) -> Result<SyncStatusView, String> {
    let label = clean_label(&label)?;
    let client = SyncClient::connect(&app).await?;
    if load_state(&app)?.is_some() {
        return Err("Sesame Sync is already set up on this device.".into());
    }
    match client.state().await {
        Err(SyncError::NotFound) => {}
        Ok(_) => {
            return Err(
                "This account already has a synced vault. Join it with a code from another device."
                    .into(),
            )
        }
        Err(other) => return Err(present(other)),
    }
    let path = identity_file(&app)?;
    let identity = match DeviceIdentity::load(&path) {
        Ok(existing) => existing,
        Err(_) => {
            let generated = DeviceIdentity::generate()?;
            generated.save(&path)?;
            generated
        }
    };
    let (vault_id, sealed) = {
        let session = vault
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session
            .as_ref()
            .ok_or("Unlock Sesame before setting up Sync.")?;
        let vault_id = vault_id_of(unlocked)?;
        let sealed = unlocked.expose_vault_key(|key| {
            seal_label(key, &vault_id, &identity.device_id, &label).map_err(present_proof)
        })?;
        (vault_id, sealed)
    };
    let entry = create_entry(&identity, &vault_id, &sealed);
    DeviceList::verify(std::slice::from_ref(&entry)).map_err(present_proof)?;
    client
        .create_vault(&identity, &entry)
        .await
        .map_err(present)?;
    let mut state = SyncState::new(&vault_id, &identity.device_id);
    state.entries = vec![entry];
    state.activated_epoch = 1;
    save_state(&app, &state)?;
    let mut view = status("approved");
    view.enrolled = true;
    view.vault_epoch = 1;
    Ok(view)
}

#[tauri::command]
pub async fn sync_disable(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
    master_password: String,
    force: Option<bool>,
) -> Result<(), String> {
    let local = load_join_state(&app)?;
    if local.is_some() && !force.unwrap_or(false) {
        super::sync_transfer::leave_vault(&app, &vault, &master_password).await?;
    }
    forget_everything(&app)
}

#[tauri::command]
pub async fn sync_reset_vault(app: AppHandle) -> Result<(), String> {
    let client = SyncClient::connect(&app).await?;
    let identity = this_identity(&app)?;
    let server = client.state().await.map_err(present)?;
    client
        .reset(&identity, server.vault_epoch)
        .await
        .map_err(present)?;
    crate::sync::state::forget_protected(&state_file(&app)?)
}

#[cfg(test)]
mod status_tests {
    use super::*;
    use crate::adapters::network::test_server::{Reply, TestServer};

    #[test]
    fn an_unpaired_device_shows_setup_without_claiming_membership_or_reading_history() {
        for identity_present in [false, true] {
            let server = TestServer::start(|request| {
                assert_eq!(request.path, "/v1/sync/state");
                Reply::json(403, &serde_json::json!({"error":{"code":"sync_forbidden"}}))
            });
            let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
            let view = tauri::async_runtime::block_on(initial_status(&client, identity_present))
                .expect("an unpaired device can show setup");
            assert_eq!(view.state, "not_enrolled");
            assert!(!view.enrolled);
            assert!(view.devices.is_empty());
            assert_eq!(view.revision, 0);
            assert!(view.alarm.is_none());
            assert_eq!(server.requests().len(), 1);
        }
    }

    #[test]
    fn an_unpaired_device_preserves_service_and_authentication_errors() {
        for (status, code) in [(401, "desktop_token_invalid"), (403, "sync_unavailable")] {
            let server = TestServer::start(move |_| {
                Reply::json(status, &serde_json::json!({"error":{"code":code}}))
            });
            let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
            assert!(tauri::async_runtime::block_on(initial_status(&client, false)).is_err());
        }
    }
}

#[cfg(test)]
mod local_status_tests {
    use super::{local_status_for, never_turned_on};
    use crate::sync::state::SyncState;

    #[test]
    fn a_device_that_never_turned_sync_on_sends_nothing_to_find_out() {
        assert!(never_turned_on(false, false));
    }

    #[test]
    fn the_local_status_comes_from_the_files_on_this_device_alone() {
        let state = SyncState::new("vault0000000000000001", "device000000000000001");
        assert_eq!(
            local_status_for(Some(&state), true, false).state,
            "approved"
        );
        assert_eq!(local_status_for(Some(&state), false, false).revision, 0);
        assert_eq!(local_status_for(None, true, false).state, "pairing");
        assert_eq!(local_status_for(None, false, false).state, "not_enrolled");
    }

    #[test]
    fn unsynced_changes_are_reported_only_for_a_vault_that_syncs() {
        let state = SyncState::new("vault0000000000000001", "device000000000000001");
        assert!(local_status_for(Some(&state), true, true).unsynced);
        assert!(!local_status_for(Some(&state), true, false).unsynced);
        assert!(!local_status_for(None, true, true).unsynced);
        assert!(!local_status_for(None, false, true).unsynced);
    }

    #[test]
    fn a_device_with_a_synced_vault_or_a_pairing_in_progress_asks_the_service() {
        assert!(!never_turned_on(true, true));
        assert!(!never_turned_on(true, false));
        assert!(!never_turned_on(false, true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entitlement_refusal_carries_its_code_and_a_readable_message() {
        assert_eq!(
            present(SyncError::NotEntitled),
            "sync_not_entitled:This account's subscription does not include Sesame Sync."
        );
    }
}
