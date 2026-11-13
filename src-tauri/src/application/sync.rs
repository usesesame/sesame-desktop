use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use zeroize::Zeroize;

use crate::sync::canonical::{ProofError, ProofKind};
use crate::sync::client::{StateView, SyncClient, SyncError};
use crate::sync::devicelist::DeviceList;
use crate::sync::engine::{
    check_peer_checkpoints, create_entry, key_entry, oldest_revision_to_compare, open_label,
    seal_label, verify_server_view, PeerView, ServedCheckpoint, ServerView, VerifiedUpdate,
};
use crate::sync::header::{verify_header_chain, Header};
use crate::sync::identity::DeviceIdentity;
use crate::sync::key_change::PreparedKeyChange;
use crate::sync::state::SyncState;
use crate::vault::crypto::{bytes_match, default_kdf_params, derive_key, encrypt_bytes};
use crate::vault::util::generate_recovery_kit;
use crate::vault::{UnlockedVault, VaultResult, VaultState, RECOVERY_WRAP_AAD, WRAP_AAD};

pub(crate) const KEY_CHANGE_PENDING: &str =
    "This device has not finished changing the vault key. Open Sync and finish it before syncing.";

pub(crate) const NOT_ACTIVATED: &str =
    "This device has not taken the new vault key yet. Open Sync and take it.";

pub(crate) struct SyncStore {
    data_dir: PathBuf,
}

impl SyncStore {
    pub(crate) fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    pub(crate) fn state_path(&self) -> PathBuf {
        crate::sync::state::state_path(&self.data_dir)
    }

    pub(crate) fn identity_path(&self) -> PathBuf {
        crate::sync::identity::identity_path(&self.data_dir)
    }

    pub(crate) fn journal_path(&self) -> PathBuf {
        crate::sync::rekey_journal::journal_path(&self.data_dir)
    }

    pub(crate) fn backup_dir(&self) -> PathBuf {
        crate::sync::conflict_backup::backup_dir(&self.data_dir)
    }

    pub(crate) fn floor_confirmed_at(&self) -> Option<u64> {
        crate::sync::floor::confirmed_at(&crate::sync::floor::floor_path(&self.data_dir))
    }

    pub(crate) fn load_join_state(&self) -> VaultResult<Option<SyncState>> {
        Ok(crate::sync::state::read_protected(&self.state_path()))
    }

    pub(crate) fn load_state(&self) -> VaultResult<Option<SyncState>> {
        let state = self.load_join_state()?;
        if let Some(state) = &state {
            state.require_join_complete()?;
        }
        Ok(state)
    }

    pub(crate) fn save_state(&self, state: &SyncState) -> VaultResult<()> {
        crate::sync::state::write_protected(&self.state_path(), state)
    }

    pub(crate) fn forget_state(&self) -> VaultResult<()> {
        crate::sync::state::forget_protected(&self.state_path())
    }

    pub(crate) fn identity_present(&self) -> bool {
        self.identity_path().exists()
    }

    pub(crate) fn this_identity(&self) -> VaultResult<DeviceIdentity> {
        DeviceIdentity::load(&self.identity_path())
            .map_err(|_| "Set up Sesame Sync on this device first.".to_string())
    }

    pub(crate) fn pending_key_change(&self) -> bool {
        crate::sync::rekey_journal::is_pending(&self.journal_path())
    }

    pub(crate) fn require_no_pending_key_change(&self) -> VaultResult<()> {
        if self.pending_key_change() {
            return Err(KEY_CHANGE_PENDING.to_string());
        }
        Ok(())
    }

    pub(crate) fn forget_everything(&self) -> VaultResult<()> {
        crate::sync::rekey_journal::forget(&self.journal_path())?;
        crate::sync::identity::forget(&self.identity_path())?;
        crate::sync::state::forget_protected(&self.state_path())
    }
}

pub(crate) fn present(error: SyncError) -> String {
    match error {
        SyncError::NotEntitled => format!("sync_not_entitled:{}", SyncError::NotEntitled),
        SyncError::Conflict => "sync_conflict:0".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn present_proof(error: ProofError) -> String {
    match error.kind {
        ProofKind::Invalid => error.to_string(),
        ProofKind::DeviceList | ProofKind::History => format!("sync_fork:{error}"),
    }
}

pub(crate) struct Refreshed {
    pub(crate) server: StateView,
    pub(crate) update: VerifiedUpdate,
    pub(crate) confirmed_at: Option<u64>,
    pub(crate) peer_checks_skipped: bool,
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub(crate) fn require_activated(refreshed: &Refreshed) -> Result<(), String> {
    if refreshed.server.device_state != "approved" {
        return Err("This device is not approved to sync.".into());
    }
    if refreshed.server.activated_epoch != refreshed.server.vault_epoch {
        return Err(NOT_ACTIVATED.into());
    }
    Ok(())
}

pub(crate) fn local_payload_bytes(vault: &UnlockedVault) -> Result<(Vec<u8>, usize), String> {
    let payload = vault.open_payload()?;
    let bytes = serde_json::to_vec(&*payload)
        .map_err(|_| "Sesame could not prepare the vault for sync.".to_string())?;
    Ok((bytes, payload.entries.len()))
}

pub(crate) fn verify_master_password(
    vault: &UnlockedVault,
    master_password: &str,
) -> Result<(), String> {
    let mut confirmed = crate::vault::crypto::unwrap_with_password(
        master_password,
        &vault.kdf,
        &vault.key_wrap,
        WRAP_AAD,
    )?
    .ok_or("That master password is not correct.")?;
    let matches = vault.expose_vault_key(|key| Ok(bytes_match(confirmed.as_slice(), key)))?;
    confirmed.zeroize();
    if !matches {
        return Err("That master password is not correct.".into());
    }
    Ok(())
}

pub(crate) fn prepare_recovery(
    key: &[u8; 32],
) -> Result<(String, crate::sync::key_change::PreparedRecovery), String> {
    let kit = generate_recovery_kit()?;
    let kdf = default_kdf_params();
    let wrapping_key = zeroize::Zeroizing::new(derive_key(&kit, &kdf)?);
    let wrap = encrypt_bytes(&wrapping_key, key, RECOVERY_WRAP_AAD)?;
    Ok((kit, crate::sync::key_change::PreparedRecovery { wrap, kdf }))
}

pub(crate) fn vault_id_of(vault: &UnlockedVault) -> Result<String, String> {
    let payload = vault.open_payload()?;
    payload.vault_id.clone().ok_or_else(|| {
        "This vault has no identity yet. Lock and unlock it once, then try again.".to_string()
    })
}

pub(crate) fn clean_label(label: &str) -> Result<String, String> {
    let label = label.trim().to_string();
    if label.is_empty() || label.chars().count() > crate::sync::engine::MAX_LABEL_CHARS {
        return Err("Give this device a name of 1 to 64 characters.".into());
    }
    Ok(label)
}

pub(crate) fn signed_revision(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncTransferResult {
    pub revision: i64,
    pub vault_epoch: i64,
    pub entry_count: usize,
}

pub(crate) fn transfer_result(revision: u64, epoch: u64, entries: usize) -> SyncTransferResult {
    SyncTransferResult {
        revision: signed_revision(revision),
        vault_epoch: signed_revision(epoch),
        entry_count: entries,
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncDeviceView {
    pub device_id: String,
    pub label: String,
    pub state: String,
    pub is_this_device: bool,
    pub added_index: u64,
    pub newer_key: bool,
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
    pub peer_checks_skipped: bool,
    pub floor_confirmed_at: Option<u64>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncLocalStatusView {
    pub state: String,
    pub revision: u64,
    pub unsynced: bool,
}

pub(crate) fn peer_history_outcome(
    fetched: Option<Vec<Header>>,
    head: Option<&Header>,
) -> (Vec<Header>, bool) {
    let Some(plain) = fetched else {
        return (Vec::new(), true);
    };
    let reaches_head = match (plain.last(), head) {
        (Some(last), Some(head)) => last.digest() == head.digest(),
        _ => false,
    };
    if reaches_head {
        (plain, false)
    } else {
        (Vec::new(), true)
    }
}

async fn history_for_peers(
    client: &SyncClient,
    update: &VerifiedUpdate,
    own_device_id: &str,
    checkpoints: &[ServedCheckpoint],
) -> Result<(Vec<Header>, bool), String> {
    let Some(oldest) = oldest_revision_to_compare(update.head.as_ref(), own_device_id, checkpoints)
    else {
        return Ok((Vec::new(), false));
    };
    let Ok(served) = client.headers(oldest.saturating_sub(1)).await else {
        return Ok(peer_history_outcome(None, update.head.as_ref()));
    };
    let plain: Vec<Header> = served.into_iter().map(|item| item.header).collect();
    verify_header_chain(&update.list, None, &plain).map_err(present_proof)?;
    Ok(peer_history_outcome(Some(plain), update.head.as_ref()))
}

pub(crate) async fn refresh(client: &SyncClient, state: &SyncState) -> Result<Refreshed, String> {
    let peer_checkpoints = client.checkpoints().await.ok();
    let mut peer_checks_skipped = peer_checkpoints.is_none();
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
            let (history, history_missing) =
                history_for_peers(client, &update, &state.device_id, &checkpoints).await?;
            peer_checks_skipped |= history_missing;
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
        peer_checks_skipped,
    })
}

pub(crate) fn names_for(
    list: &DeviceList,
    remembered: &BTreeMap<String, String>,
    vault_id: &str,
    vault_key: Option<&[u8; 32]>,
) -> BTreeMap<String, String> {
    let usable = |name: &String| {
        !name.is_empty() && name.chars().count() <= crate::sync::engine::MAX_LABEL_CHARS
    };
    list.all_members()
        .into_iter()
        .filter_map(|member| {
            let opened = vault_key
                .and_then(|key| open_label(key, vault_id, &member.device_id, &member.sealed_label));
            opened
                .or_else(|| remembered.get(&member.device_id).cloned())
                .filter(usable)
                .map(|name| (member.device_id.clone(), name))
        })
        .collect()
}

pub(crate) fn views_from(
    list: &DeviceList,
    state: &SyncState,
    names: &BTreeMap<String, String>,
) -> Vec<SyncDeviceView> {
    let mut devices: Vec<SyncDeviceView> = list
        .all_members()
        .into_iter()
        .map(|member| {
            let label = names
                .get(&member.device_id)
                .cloned()
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
                newer_key: is_newer_key(&member.package_key),
            }
        })
        .collect();
    devices.sort_by_key(|device| device.added_index);
    devices
}

pub(crate) fn is_newer_key(encoded: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .is_ok_and(|bytes| bytes.len() == crate::sync::xwing::PUBLIC_KEY_BYTES)
}

fn remember_names(store: &SyncStore, names: &BTreeMap<String, String>) {
    let Ok(Some(mut current)) = store.load_state() else {
        return;
    };
    if current.remember_names(names).is_ok() {
        let _ = store.save_state(&current);
    }
}

pub(crate) fn status(state: &str) -> SyncStatusView {
    SyncStatusView {
        enrolled: false,
        state: state.to_string(),
        vault_epoch: 0,
        revision: 0,
        devices: Vec::new(),
        needs_new_key: false,
        alarm: None,
        confirmed_at: None,
        peer_checks_skipped: false,
        floor_confirmed_at: None,
    }
}

pub(crate) fn never_enrolled_status() -> SyncStatusView {
    status("not_enrolled")
}

pub(crate) fn sync_status_needs_service(local_present: bool, identity_present: bool) -> bool {
    !never_turned_on(local_present, identity_present)
}

pub(crate) async fn initial_status(
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

pub(crate) fn never_turned_on(has_state: bool, has_identity: bool) -> bool {
    !has_state && !has_identity
}

pub(crate) fn local_status_for(
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

pub(crate) fn local_status_in_state(
    state: &VaultState,
    store: &SyncStore,
) -> VaultResult<SyncLocalStatusView> {
    let local = store.load_state()?;
    let identity_present = store.identity_present();
    let unsynced = match &local {
        Some(local) => {
            let session = state
                .session
                .lock()
                .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
            session
                .as_ref()
                .and_then(|unlocked| local_payload_bytes(unlocked).ok())
                .is_some_and(|(plaintext, _)| local.has_local_changes(&plaintext))
        }
        None => false,
    };
    Ok(local_status_for(local.as_ref(), identity_present, unsynced))
}

pub(crate) fn needs_new_key(
    device_state: &str,
    activated_epoch: u64,
    vault_epoch: u64,
    pending_key_change: bool,
) -> bool {
    device_state == "approved" && (activated_epoch < vault_epoch || pending_key_change)
}

pub(crate) fn device_is_removed(current_member: bool, server_state: &str) -> bool {
    !current_member || server_state != "approved"
}

pub(crate) async fn sync_status_in_state(
    vault: &VaultState,
    store: &SyncStore,
    local: Option<SyncState>,
    identity_present: bool,
    client: &SyncClient,
) -> Result<SyncStatusView, String> {
    let Some(local) = local else {
        return initial_status(client, identity_present).await;
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
    view.floor_confirmed_at = store.floor_confirmed_at();
    let (list, state) = match refresh(client, &local).await {
        Ok(refreshed) => {
            view.confirmed_at = refreshed.confirmed_at;
            view.peer_checks_skipped = refreshed.peer_checks_skipped;
            let mut next = local.clone();
            next.entries = refreshed.update.entries.clone();
            if next.entries != local.entries {
                store.save_state(&next)?;
            }
            (refreshed.update.list, next)
        }
        Err(message) => {
            let list = local.list().map_err(present_proof)?;
            view.alarm = Some(message.trim_start_matches("sync_fork:").to_string());
            (list, local.clone())
        }
    };
    let remembered = state.remembered_names();
    let names = {
        let session = vault
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        match session.as_ref() {
            Some(unlocked) => unlocked.expose_vault_key(|key| {
                Ok(names_for(&list, &remembered, &state.vault_id, Some(key)))
            })?,
            None => names_for(&list, &remembered, &state.vault_id, None),
        }
    };
    if names != remembered && !names.is_empty() {
        remember_names(store, &names);
    }
    view.devices = views_from(&list, &state, &names);
    let this_device = list.member(&state.device_id);
    if device_is_removed(
        this_device.is_some_and(|member| member.removed_index == 0),
        &server.device_state,
    ) {
        view.state = "removed".to_string();
    }
    view.needs_new_key = needs_new_key(
        &server.device_state,
        server.activated_epoch,
        server.vault_epoch,
        store.pending_key_change(),
    );
    Ok(view)
}

pub(crate) async fn create_vault_in_state(
    state: &VaultState,
    store: &SyncStore,
    client: &SyncClient,
    label: &str,
) -> Result<SyncStatusView, String> {
    if store.load_state()?.is_some() {
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
    let path = store.identity_path();
    let identity = crate::sync::identity::load_or_create(&path)?;
    let (vault_id, sealed) = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session
            .as_ref()
            .ok_or("Unlock Sesame before setting up Sync.")?;
        let vault_id = vault_id_of(unlocked)?;
        let sealed = unlocked.expose_vault_key(|key| {
            seal_label(key, &vault_id, &identity.device_id, label).map_err(present_proof)
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
    store.save_state(&state)?;
    let mut view = status("approved");
    view.enrolled = true;
    view.vault_epoch = 1;
    Ok(view)
}

pub(crate) async fn reset_vault_in_state(
    store: &SyncStore,
    client: &SyncClient,
) -> Result<(), String> {
    let identity = store.this_identity()?;
    let server = client.state().await.map_err(present)?;
    client
        .reset(&identity, server.vault_epoch)
        .await
        .map_err(present)?;
    store.forget_state()
}

pub(crate) async fn upgrade_device_key_in_state(
    store: &SyncStore,
    client: &SyncClient,
) -> Result<(), String> {
    store.require_no_pending_key_change()?;
    let identity = store.this_identity()?;
    let local = store
        .load_state()?
        .ok_or("Set up Sesame Sync on this device first.")?;
    let refreshed = refresh(client, &local).await?;
    require_activated(&refreshed)?;
    let list = &refreshed.update.list;
    let member = list
        .member(&identity.device_id)
        .filter(|member| member.removed_index == 0)
        .ok_or("This device is not part of the vault.")?;
    if is_newer_key(&member.package_key) {
        return Err("This device already has the newer key.".into());
    }
    let identity = identity.with_hybrid_key()?;
    identity.save(&store.identity_path())?;
    let entry = key_entry(
        &identity,
        list,
        &URL_SAFE_NO_PAD.encode(identity.package_public_key()),
    )
    .map_err(present_proof)?;
    client
        .upgrade_device_key(&identity, &entry)
        .await
        .map_err(present)?;
    let mut next = local;
    next.entries = refreshed.update.entries;
    next.entries.push(entry);
    store.save_state(&next)?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncPreparedKit {
    pub recovery_kit: String,
}

pub(crate) fn prepare_key_change_in_state(
    state: &VaultState,
    store: &SyncStore,
    prepared: &PreparedKeyChange,
    master_password: &str,
) -> Result<SyncPreparedKit, String> {
    store.require_no_pending_key_change()?;
    store
        .load_state()?
        .ok_or("Set up Sesame Sync on this device first.")?;
    {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session
            .as_ref()
            .ok_or("Unlock Sesame before changing the vault key.")?;
        verify_master_password(unlocked, master_password)?;
    }
    let mut key = [0u8; 32];
    crate::vault::util::fill_secret(&mut key)?;
    let made = prepare_recovery(&key);
    let result = made.map(|(kit, recovery)| {
        prepared.stage(&key, recovery, Instant::now());
        SyncPreparedKit { recovery_kit: kit }
    });
    key.zeroize();
    result
}

pub(crate) fn refuse_self_removal(device_id: &str, own_device_id: &str) -> Result<(), String> {
    if device_id == own_device_id {
        return Err("Turn Sesame Sync off on this device instead of removing it.".into());
    }
    Ok(())
}

pub(crate) fn disable_needs_leave(local_present: bool, force: bool) -> bool {
    local_present && !force
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncCoordinatorView {
    pub phase: String,
    pub halt: String,
    pub conflict_revision: i64,
    pub pending: bool,
    pub last_success_revision: i64,
    pub consecutive_failures: u32,
    pub downloads_applied: u32,
}

pub(crate) fn coordinator_view(status: &crate::sync::coordinator::Status) -> SyncCoordinatorView {
    use crate::sync::coordinator::{Halt, Phase};

    let (phase, halt, conflict_revision) = match &status.phase {
        Phase::Idle => ("idle", "", 0),
        Phase::Working => ("working", "", 0),
        Phase::Retrying { .. } => ("retrying", "", 0),
        Phase::GaveUp => ("gave_up", "", 0),
        Phase::Paused => ("paused", "locked", 0),
        Phase::Halted(Halt::Revoked) => ("halted", "revoked", 0),
        Phase::Halted(Halt::NotEntitled) => ("halted", "not_entitled", 0),
        Phase::Halted(Halt::Incompatible) => ("halted", "incompatible", 0),
        Phase::Halted(Halt::FloorDamaged) => ("halted", "floor_damaged", 0),
        Phase::Halted(Halt::Fork) => ("halted", "fork", 0),
        Phase::Halted(Halt::Locked) => ("halted", "locked", 0),
        Phase::Halted(Halt::Conflict { server_revision }) => {
            ("halted", "conflict", *server_revision)
        }
        Phase::Halted(Halt::NeedsNewKey) => ("halted", "needs_new_key", 0),
    };
    SyncCoordinatorView {
        phase: phase.to_string(),
        halt: halt.to_string(),
        conflict_revision,
        pending: status.pending,
        last_success_revision: status.last_success_revision.unwrap_or(0),
        consecutive_failures: status.consecutive_failures,
        downloads_applied: status.downloads_applied,
    }
}

pub(crate) fn require_no_service_connection(connected: bool) -> VaultResult<()> {
    if connected {
        return Err(
            "This desktop is already connected. Disconnect it before pairing with another server."
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn connection_ended_state(
    connection: &crate::vault::ServiceConnectionFile,
    now: i64,
) -> &'static str {
    match connection.expires_at {
        Some(expires_at) if i64::try_from(expires_at).is_ok_and(|expires_at| expires_at <= now) => {
            "expired"
        }
        _ => "revoked",
    }
}
