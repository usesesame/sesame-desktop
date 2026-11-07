use std::path::PathBuf;

use tauri::AppHandle;

use crate::application::sync::SyncStore;
use crate::sync::client::SyncClient;
use crate::sync::identity::DeviceIdentity;
use crate::sync::state::SyncState;
use crate::vault::{VaultResult, VaultState};

pub(super) use crate::application::sync::{
    clean_label, present, present_proof, refresh, vault_id_of,
};
pub use crate::application::sync::{SyncLocalStatusView, SyncStatusView};

pub(super) fn local_data_dir(app: &AppHandle) -> VaultResult<PathBuf> {
    use tauri::Manager;
    app.path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())
}

pub(super) fn identity_file(app: &AppHandle) -> VaultResult<PathBuf> {
    Ok(SyncStore::new(local_data_dir(app)?).identity_path())
}

pub(super) fn this_identity(app: &AppHandle) -> VaultResult<DeviceIdentity> {
    SyncStore::new(local_data_dir(app)?).this_identity()
}

pub(super) fn load_state(app: &AppHandle) -> VaultResult<Option<SyncState>> {
    SyncStore::new(local_data_dir(app)?).load_state()
}

pub(super) fn load_join_state(app: &AppHandle) -> VaultResult<Option<SyncState>> {
    SyncStore::new(local_data_dir(app)?).load_join_state()
}

pub(super) fn save_state(app: &AppHandle, state: &SyncState) -> VaultResult<()> {
    SyncStore::new(local_data_dir(app)?).save_state(state)
}

pub(super) fn require_no_pending_key_change(app: &AppHandle) -> VaultResult<()> {
    SyncStore::new(local_data_dir(app)?).require_no_pending_key_change()
}

pub(super) fn forget_everything(app: &AppHandle) -> VaultResult<()> {
    SyncStore::new(local_data_dir(app)?).forget_everything()
}

#[tauri::command]
pub async fn sync_local_status(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
) -> Result<SyncLocalStatusView, String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    crate::application::sync::local_status_in_state(&vault, &store)
}

#[tauri::command]
pub async fn sync_status(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
) -> Result<SyncStatusView, String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    let local = store.load_join_state()?;
    let identity_present = store.identity_present();
    if !crate::application::sync::sync_status_needs_service(local.is_some(), identity_present) {
        return Ok(crate::application::sync::never_enrolled_status());
    }
    let client = SyncClient::connect(&app).await?;
    crate::application::sync::sync_status_in_state(&vault, &store, local, identity_present, &client)
        .await
}

#[tauri::command]
pub async fn sync_create_vault(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
    label: String,
) -> Result<SyncStatusView, String> {
    let label = clean_label(&label)?;
    let client = SyncClient::connect(&app).await?;
    let store = SyncStore::new(local_data_dir(&app)?);
    crate::application::sync::create_vault_in_state(&vault, &store, &client, &label).await
}

#[tauri::command]
pub async fn sync_disable(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
    master_password: String,
    force: Option<bool>,
) -> Result<(), String> {
    let local = load_join_state(&app)?;
    if crate::application::sync::disable_needs_leave(local.is_some(), force.unwrap_or(false)) {
        super::sync_transfer::leave_vault(&app, &vault, &master_password).await?;
    }
    forget_everything(&app)?;
    coordinator.resume();
    Ok(())
}

#[tauri::command]
pub async fn sync_reset_vault(app: AppHandle) -> Result<(), String> {
    let client = SyncClient::connect(&app).await?;
    let store = SyncStore::new(local_data_dir(&app)?);
    crate::application::sync::reset_vault_in_state(&store, &client).await
}

#[cfg(test)]
mod status_tests {
    use super::*;
    use crate::adapters::network::test_server::{Reply, TestServer};
    use crate::application::sync::initial_status;

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
    use crate::application::sync::{local_status_for, never_turned_on};
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
    use crate::sync::client::SyncError;

    #[test]
    fn an_entitlement_refusal_carries_its_code_and_a_readable_message() {
        assert_eq!(
            present(SyncError::NotEntitled),
            "sync_not_entitled:This account's subscription does not include Sesame Sync."
        );
    }
}

#[cfg(test)]
mod peer_history_tests {
    use crate::application::sync::peer_history_outcome;

    #[test]
    fn a_failed_history_fetch_is_reported_as_skipped_and_never_as_checked() {
        let (history, skipped) = peer_history_outcome(None, None);
        assert!(history.is_empty());
        assert!(skipped);
    }

    #[test]
    fn a_history_that_does_not_reach_the_head_is_reported_as_skipped() {
        let (history, skipped) = peer_history_outcome(Some(Vec::new()), None);
        assert!(history.is_empty());
        assert!(skipped);
    }
}

#[cfg(test)]
mod device_name_tests {
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    use super::*;
    use crate::application::sync::{names_for, views_from};
    use crate::sync::devicelist::DeviceList;
    use crate::sync::engine::{add_entry, create_entry, seal_label, NewDevice};

    const VAULT: &str = "vaultAAAAAAAAAAAA01";
    const FIRST_KEY: [u8; 32] = [3u8; 32];
    const SECOND_KEY: [u8; 32] = [4u8; 32];

    struct Pair {
        list: DeviceList,
        laptop: String,
        desktop: String,
    }

    fn pair() -> Pair {
        let laptop = DeviceIdentity::generate().expect("identity");
        let desktop = DeviceIdentity::generate().expect("identity");
        let sealed = |device: &DeviceIdentity, name: &str| {
            seal_label(&FIRST_KEY, VAULT, &device.device_id, name).expect("label")
        };
        let create = create_entry(&laptop, VAULT, &sealed(&laptop, "Fictional laptop"));
        let mut list = DeviceList::verify(std::slice::from_ref(&create)).expect("list");
        let added = add_entry(
            &laptop,
            &list,
            &NewDevice {
                device_id: &desktop.device_id,
                signing_key: &URL_SAFE_NO_PAD.encode(desktop.signing_public_key()),
                package_key: &URL_SAFE_NO_PAD.encode(desktop.package_public_key()),
            },
            &sealed(&desktop, "Fictional desktop"),
            0,
        )
        .expect("add");
        list.extend(&added).expect("extend");
        Pair {
            list,
            laptop: laptop.device_id.clone(),
            desktop: desktop.device_id.clone(),
        }
    }

    fn name_of(names: &BTreeMap<String, String>, id: &str) -> Option<String> {
        names.get(id).cloned()
    }

    #[test]
    fn names_are_read_with_the_key_that_sealed_them() {
        let pair = pair();
        let names = names_for(&pair.list, &BTreeMap::new(), VAULT, Some(&FIRST_KEY));
        assert_eq!(
            name_of(&names, &pair.laptop).as_deref(),
            Some("Fictional laptop")
        );
        assert_eq!(
            name_of(&names, &pair.desktop).as_deref(),
            Some("Fictional desktop")
        );
    }

    #[test]
    fn after_a_key_change_a_name_this_device_already_read_is_still_shown() {
        let pair = pair();
        let remembered = names_for(&pair.list, &BTreeMap::new(), VAULT, Some(&FIRST_KEY));
        let after = names_for(&pair.list, &remembered, VAULT, Some(&SECOND_KEY));
        assert_eq!(after, remembered);
    }

    #[test]
    fn a_name_that_was_never_readable_stays_unknown_and_nothing_is_guessed() {
        let pair = pair();
        let names = names_for(&pair.list, &BTreeMap::new(), VAULT, Some(&SECOND_KEY));
        assert!(names.is_empty());
        let locked = names_for(&pair.list, &BTreeMap::new(), VAULT, None);
        assert!(locked.is_empty());
    }

    #[test]
    fn a_remembered_name_for_a_device_that_is_not_in_the_list_is_dropped() {
        let pair = pair();
        let mut remembered = BTreeMap::new();
        remembered.insert(
            "someOtherDevice0000001".to_string(),
            "Fictional phone".to_string(),
        );
        remembered.insert(pair.desktop.clone(), "Fictional desktop".to_string());
        let names = names_for(&pair.list, &remembered, VAULT, Some(&SECOND_KEY));
        assert_eq!(names.len(), 1);
        assert_eq!(
            name_of(&names, &pair.desktop).as_deref(),
            Some("Fictional desktop")
        );
    }

    #[test]
    fn a_name_the_current_key_can_open_replaces_the_one_that_was_remembered() {
        let pair = pair();
        let mut remembered = BTreeMap::new();
        remembered.insert(pair.laptop.clone(), "Old remembered name".to_string());
        let names = names_for(&pair.list, &remembered, VAULT, Some(&FIRST_KEY));
        assert_eq!(
            name_of(&names, &pair.laptop).as_deref(),
            Some("Fictional laptop")
        );
    }

    #[test]
    fn a_remembered_name_that_is_empty_or_too_long_is_not_shown() {
        let pair = pair();
        let mut remembered = BTreeMap::new();
        remembered.insert(pair.laptop.clone(), String::new());
        remembered.insert(
            pair.desktop.clone(),
            "x".repeat(crate::sync::engine::MAX_LABEL_CHARS + 1),
        );
        let names = names_for(&pair.list, &remembered, VAULT, Some(&SECOND_KEY));
        assert!(names.is_empty());
    }

    #[test]
    fn the_device_view_uses_the_remembered_name_or_says_a_device() {
        let pair = pair();
        let state = SyncState::new(VAULT, &pair.laptop);
        let mut names = BTreeMap::new();
        names.insert(pair.laptop.clone(), "Fictional laptop".to_string());
        let views = views_from(&pair.list, &state, &names);
        assert_eq!(views.len(), 2);
        let laptop = views
            .iter()
            .find(|view| view.device_id == pair.laptop)
            .expect("laptop");
        let desktop = views
            .iter()
            .find(|view| view.device_id == pair.desktop)
            .expect("desktop");
        assert_eq!(laptop.label, "Fictional laptop");
        assert!(laptop.is_this_device);
        assert_eq!(desktop.label, "A device");
    }

    #[test]
    fn remembered_names_survive_a_save_and_are_not_written_as_plain_json() {
        let pair = pair();
        let mut state = SyncState::new(VAULT, &pair.laptop);
        let mut names = BTreeMap::new();
        names.insert(pair.desktop.clone(), "Fictional desktop".to_string());
        state.remember_names(&names).expect("remembered");
        let stored = serde_json::to_string(&state).expect("json");
        assert!(stored.contains("names"));
        assert!(!stored.contains("Fictional desktop"));
        let reloaded: SyncState = serde_json::from_str(&stored).expect("state");
        assert_eq!(reloaded.remembered_names(), names);
        state.remember_names(&BTreeMap::new()).expect("cleared");
        assert!(!serde_json::to_string(&state)
            .expect("json")
            .contains("names"));
    }

    #[test]
    fn a_damaged_names_value_is_forgotten_and_does_not_break_the_state() {
        let pair = pair();
        let mut state = SyncState::new(VAULT, &pair.laptop);
        state.names = Some("not base64 !!".to_string());
        assert!(state.remembered_names().is_empty());
        state.names = Some(URL_SAFE_NO_PAD.encode(b"not json"));
        assert!(state.remembered_names().is_empty());
    }
}
