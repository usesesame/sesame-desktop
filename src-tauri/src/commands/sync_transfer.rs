use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use tauri::AppHandle;
use zeroize::Zeroize;

use super::sync::{
    journal_file, load_state, local_data_dir, present, present_proof, record_checkpoint_if_due,
    refresh, require_no_pending_key_change, save_state, this_identity, unix_now, vault_id_of,
    Refreshed,
};
use super::sync_adopt::{adopt, verify_master_password};
use crate::sync::client::SyncClient;
use crate::sync::devicelist::DeviceList;
use crate::sync::engine::{build_header, open_label, plan_header, remove_entry, verify_accepted};
use crate::sync::header::Header;
use crate::sync::rekey_journal::{self, Journal, Outcome};
use crate::sync::request::KeyPackageV3;
use crate::sync::state::{payload_digest, SyncState};
use crate::vault::{VaultResult, VaultState};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncTransferResult {
    pub revision: i64,
    pub vault_epoch: i64,
    pub entry_count: usize,
}

const SEAL_OVERHEAD_BYTES: usize = 16;

fn signed_revision(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn transfer_result(revision: u64, epoch: u64, entries: usize) -> SyncTransferResult {
    SyncTransferResult {
        revision: signed_revision(revision),
        vault_epoch: signed_revision(epoch),
        entry_count: entries,
    }
}

fn decode_bytes(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "A Sync value is not valid base64.".to_string())
}

fn require_activated(refreshed: &Refreshed) -> Result<(), String> {
    if refreshed.server.device_state != "approved" {
        return Err("This device is not approved to sync.".into());
    }
    if refreshed.server.activated_epoch != refreshed.server.vault_epoch {
        return Err(
            "This device has not taken the new vault key yet. Open Sync and take it.".into(),
        );
    }
    Ok(())
}

pub(super) fn local_payload_bytes(
    vault: &crate::vault::UnlockedVault,
) -> Result<(Vec<u8>, usize), String> {
    let payload = vault.open_payload()?;
    let bytes = serde_json::to_vec(&*payload)
        .map_err(|_| "Sesame could not prepare the vault for sync.".to_string())?;
    Ok((bytes, payload.entries.len()))
}

fn persist(
    app: &AppHandle,
    mut state: SyncState,
    refreshed_entries: Vec<crate::sync::devicelist::DeviceListEntry>,
) -> VaultResult<SyncState> {
    state.entries = refreshed_entries;
    save_state(app, &state)?;
    Ok(state)
}

async fn upload_on(
    app: &AppHandle,
    vault: &tauri::State<'_, VaultState>,
    previous: Option<Header>,
    base: &SyncState,
    client: &SyncClient,
    refreshed: Refreshed,
) -> Result<SyncTransferResult, String> {
    let identity = this_identity(app)?;
    let list = refreshed.update.list;
    let plan = plan_header(&identity.device_id, &list, previous.as_ref()).map_err(present_proof)?;
    let aad = plan.aad();
    let (blob, entry_count, plaintext_digest) = {
        let session = vault
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session.as_ref().ok_or("Unlock Sesame before syncing.")?;
        let (plaintext, entries) = local_payload_bytes(unlocked)?;
        let digest = payload_digest(&plaintext);
        let padded = crate::vault::crypto::serialize_payload(&*unlocked.open_payload()?)?;
        if padded.len() + SEAL_OVERHEAD_BYTES
            > crate::sync::canonical::MAX_CIPHERTEXT_BYTES as usize
        {
            return Err(
                "This vault is too large to sync yet. Sync accepts a vault up to 10 MiB.".into(),
            );
        }
        let blob = unlocked
            .expose_vault_key(|key| crate::vault::crypto::encrypt_bytes(key, &padded, &aad))?;
        (blob, entries, digest)
    };
    let nonce = decode_bytes(&blob.nonce)?;
    let ciphertext = decode_bytes(&blob.ciphertext)?;
    let header = build_header(&identity, &plan, &nonce, &ciphertext);
    let mut staged = base.clone();
    staged.pending_upload = Some(crate::sync::state::PendingUpload {
        header: header.clone(),
        payload_digest: plaintext_digest.clone(),
    });
    save_state(app, &staged)?;
    let accepted = client
        .upload(&identity, &header, &ciphertext)
        .await
        .map_err(present)?;
    let receipt = verify_accepted(
        &header,
        &accepted.digest,
        accepted.revision,
        &accepted.receipt,
        &accepted.accepted_at,
        client.instance_key(),
    )
    .map_err(present_proof)?;
    let mut next = base.clone();
    next.pending_upload = None;
    next.entries = refreshed.update.entries;
    next.head = Some(header.clone());
    next.payload_digest = plaintext_digest;
    next.receipt = Some(receipt);
    save_state(app, &next)?;
    Ok(transfer_result(
        header.revision,
        header.vault_epoch,
        entry_count,
    ))
}

const ALREADY_SYNCING: &str = "Sesame is already syncing. Try again in a moment.";

#[tauri::command]
pub async fn sync_upload_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
) -> Result<SyncTransferResult, String> {
    let _run = coordinator
        .begin_manual()
        .ok_or_else(|| ALREADY_SYNCING.to_string())?;
    upload_vault(app, state).await
}

/// An earlier upload may have reached the service while its answer was lost or the app stopped.
/// This settles that before anything is compared, so the upload is not mistaken for a conflict.
async fn reconcile_pending_upload(
    app: &AppHandle,
    client: &SyncClient,
    local: SyncState,
) -> Result<SyncState, String> {
    use crate::sync::state::{landed_state, pending_outcome, PendingOutcome};

    let Some(pending) = local.pending_upload.clone() else {
        return Ok(local);
    };
    let refreshed = refresh(client, &local).await?;
    let head_digest = refreshed.update.head.as_ref().map(Header::digest);
    let outcome = pending_outcome(
        &pending,
        local.head_revision(),
        refreshed.server.current_revision,
        head_digest.as_deref(),
    );
    if outcome == PendingOutcome::Landed {
        let served = client
            .headers(pending.header.revision.saturating_sub(1))
            .await
            .map_err(present)?;
        let item = served
            .into_iter()
            .find(|item| item.header.revision == pending.header.revision)
            .ok_or("The service did not list the upload this device made.")?;
        let receipt = verify_accepted(
            &pending.header,
            &item.digest,
            item.header.revision,
            &item.receipt,
            &item.accepted_at,
            client.instance_key(),
        )
        .map_err(present_proof)?;
        let next = landed_state(&local, &pending, refreshed.update.entries, receipt);
        save_state(app, &next)?;
        return Ok(next);
    }
    let mut next = local;
    next.pending_upload = None;
    next.entries = refreshed.update.entries;
    save_state(app, &next)?;
    Ok(next)
}

async fn upload_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<SyncTransferResult, String> {
    require_no_pending_key_change(&app)?;
    let client = SyncClient::connect(&app).await?;
    let local = load_state(&app)?.ok_or("Set up Sesame Sync on this device first.")?;
    let local = reconcile_pending_upload(&app, &client, local).await?;
    let refreshed = refresh(&client, &local).await?;
    require_activated(&refreshed)?;
    match crate::sync::state::decide_upload(
        local.head_revision(),
        refreshed.server.current_revision,
    ) {
        crate::sync::state::UploadDecision::Offer { .. } => {}
        crate::sync::state::UploadDecision::Conflict { server_revision } => {
            persist(&app, local, refreshed.update.entries)?;
            return Err(format!("sync_conflict:{server_revision}"));
        }
    }
    let previous = local.head.clone();
    upload_on(&app, &state, previous, &local, &client, refreshed).await
}

fn decrypt_remote(
    key: &[u8; 32],
    header: &Header,
    ciphertext_b64: &str,
) -> VaultResult<sesame_core::loader::AuthenticatedPayload> {
    let ciphertext = decode_bytes(ciphertext_b64)?;
    header
        .verify_ciphertext(&ciphertext)
        .map_err(present_proof)?;
    let blob = crate::vault::types::CipherBlob {
        nonce: header.nonce.clone(),
        ciphertext: ciphertext_b64.to_string(),
    };
    sesame_core::loader::VaultLoader::open_snapshot(header.version, key, &blob, &header.aad())
        .map_err(Into::into)
}

struct Remote {
    refreshed: Refreshed,
    header: Header,
    accepted_at: String,
    ciphertext: String,
}

async fn fetch_remote(client: &SyncClient, local: &SyncState) -> Result<Remote, String> {
    let refreshed = refresh(client, local).await?;
    let head = refreshed
        .update
        .head
        .clone()
        .ok_or("This vault has not been synced from another device yet.")?;
    let snapshot = client.snapshot().await.map_err(present)?;
    if snapshot.header.digest() != head.digest() {
        return Err(
            "sync_fork:The snapshot the service sent is not the one its history names.".into(),
        );
    }
    Ok(Remote {
        refreshed,
        header: head,
        accepted_at: snapshot.accepted_at,
        ciphertext: snapshot.ciphertext,
    })
}

#[tauri::command]
pub async fn sync_download_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
) -> Result<SyncTransferResult, String> {
    let _run = coordinator
        .begin_manual()
        .ok_or_else(|| ALREADY_SYNCING.to_string())?;
    download_vault(app, state).await
}

async fn download_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<SyncTransferResult, String> {
    require_no_pending_key_change(&app)?;
    let client = SyncClient::connect(&app).await?;
    let local = load_state(&app)?.ok_or("Set up Sesame Sync on this device first.")?;
    let remote = fetch_remote(&client, &local).await?;
    require_activated(&remote.refreshed)?;
    let current_revision = local.head_revision();
    if remote.header.revision <= current_revision && local.head.is_some() {
        persist(&app, local, remote.refreshed.update.entries)?;
        return Ok(transfer_result(
            current_revision,
            remote.header.vault_epoch,
            0,
        ));
    }
    let (applied_digest, entry_count) = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session.as_mut().ok_or("Unlock Sesame before syncing.")?;
        let (plaintext, _) = local_payload_bytes(unlocked)?;
        if local.has_local_changes(&plaintext) {
            return Err("This device has changes that are not synced yet. Upload them, or resolve the difference.".into());
        }
        let authenticated = unlocked
            .expose_vault_key(|key| decrypt_remote(key, &remote.header, &remote.ciphertext))?;
        let payload = authenticated.payload().clone();
        let entries = payload.entries.len();
        let digest = payload_digest(
            &serde_json::to_vec(&payload)
                .map_err(|_| "Sesame could not read the synced vault.".to_string())?,
        );
        crate::vault::storage::commit_payload_change(unlocked, payload)?;
        state.advance_session_epoch();
        (digest, entries)
    };
    crate::browser_fill::cancel_pending_approvals(&app);
    let mut next = local;
    next.entries = remote.refreshed.update.entries;
    next.head = Some(remote.header.clone());
    next.payload_digest = applied_digest;
    next.receipt = remote.refreshed.update.receipt;
    save_state(&app, &next)?;
    Ok(transfer_result(
        remote.header.revision,
        remote.header.vault_epoch,
        entry_count,
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncTakeKeyResult {
    pub recovery_kit: String,
}

#[tauri::command]
pub async fn sync_take_new_key(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    master_password: String,
) -> Result<SyncTakeKeyResult, String> {
    let client = SyncClient::connect(&app).await?;
    let identity = this_identity(&app)?;
    let local = load_state(&app)?.ok_or("Set up Sesame Sync on this device first.")?;
    let refreshed = refresh(&client, &local).await?;
    if refreshed.server.device_state != "approved" {
        return Err("This device is not approved to sync.".into());
    }
    let list = &refreshed.update.list;
    let epoch = list.epoch();
    match reconcile_key_change(&journal_file(&app)?, list, refreshed.server.activated_epoch)? {
        KeyChange::Adopt(journal) => {
            return adopt_journal_key(&app, &state, local, refreshed, &journal, &master_password)
                .await;
        }
        KeyChange::NotDone => return Err(KEY_CHANGE_NOT_DONE.into()),
        KeyChange::Proceed => {}
    }
    if refreshed.server.activated_epoch >= epoch {
        return Err("This device already has the current vault key.".into());
    }
    let package = client.key_package().await.map_err(present)?;
    let sender = list
        .member(&package.sender_device_id)
        .ok_or("The key package came from a device that is not in the device list.")?;
    package.verify(&sender.signing_key).map_err(present_proof)?;
    if package.recipient_device_id != identity.device_id
        || package.vault_id != local.vault_id
        || package.vault_epoch != epoch
    {
        return Err("The key package is not the one this device was promised.".into());
    }
    crate::sync::engine::verify_package_for_removal(&refreshed.update.entries, &package)
        .map_err(present_proof)?;
    let sealed = decode_bytes(&package.ciphertext)?;
    let mut opened = identity.open_key_package(&sealed, &local.vault_id, epoch)?;
    let key: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| "The synced vault key is invalid.".to_string())?;
    opened.zeroize();
    let recovery_kit = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session
            .as_mut()
            .ok_or("Unlock Sesame before taking the new key.")?;
        verify_master_password(unlocked, &master_password)?;
        let payload = unlocked.open_payload()?.clone();
        let kit = adopt(unlocked, key, payload, &master_password)?;
        state.advance_session_epoch();
        kit
    };
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    crate::commands::lifecycle::discard_pin_throttle_state(&app, &state);
    crate::browser_fill::cancel_pending_approvals(&app);
    client
        .activate(&identity, &package.digest())
        .await
        .map_err(present)?;
    let mut next = local;
    next.entries = refreshed.update.entries;
    next.activated_epoch = epoch;
    save_state(&app, &next)?;
    Ok(SyncTakeKeyResult { recovery_kit })
}

const KEY_CHANGE_NOT_DONE: &str = "The vault key change did not go through, so nothing changed. Remove the device again if you still want to.";

enum KeyChange {
    Adopt(Journal),
    NotDone,
    Proceed,
}

fn reconcile_key_change(
    path: &std::path::Path,
    list: &DeviceList,
    activated_epoch: u64,
) -> Result<KeyChange, String> {
    if !rekey_journal::is_pending(path) {
        return Ok(KeyChange::Proceed);
    }
    let journal = Journal::load(path).map_err(|error| {
        format!("{error} Turn Sesame Sync off on this device and pair it again.")
    })?;
    if journal.outcome(list) == Outcome::Adopt {
        return Ok(KeyChange::Adopt(journal));
    }
    rekey_journal::forget(path)?;
    if activated_epoch >= list.epoch() {
        return Ok(KeyChange::NotDone);
    }
    Ok(KeyChange::Proceed)
}

async fn adopt_journal_key(
    app: &AppHandle,
    state: &tauri::State<'_, VaultState>,
    local: SyncState,
    refreshed: Refreshed,
    journal: &Journal,
    master_password: &str,
) -> Result<SyncTakeKeyResult, String> {
    let mut key = journal.key();
    let adopted = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session
            .as_mut()
            .ok_or("Unlock Sesame before finishing the vault key change.")?;
        verify_master_password(unlocked, master_password).and_then(|()| {
            let payload = unlocked.open_payload()?.clone();
            let kit = adopt(unlocked, key, payload, master_password)?;
            state.advance_session_epoch();
            Ok(kit)
        })
    };
    key.zeroize();
    let recovery_kit = adopted?;
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    crate::commands::lifecycle::discard_pin_throttle_state(app, state);
    crate::browser_fill::cancel_pending_approvals(app);
    let mut next = local;
    next.entries = refreshed.update.entries;
    next.activated_epoch = journal.epoch_after;
    save_state(app, &next)?;
    rekey_journal::forget(&journal_file(app)?)?;
    Ok(SyncTakeKeyResult { recovery_kit })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRemovalResult {
    pub recovery_kit: String,
}

fn survivor_packages(
    identity: &crate::sync::identity::DeviceIdentity,
    list: &DeviceList,
    vault_id: &str,
    new_key: &[u8; 32],
    excluded: &[&str],
    epoch: u64,
    entry_digest: &str,
) -> Result<Vec<KeyPackageV3>, String> {
    let mut packages = Vec::new();
    for member in list.current() {
        if excluded.contains(&member.device_id.as_str()) {
            continue;
        }
        let recipient = decode_bytes(&member.package_key)?;
        let sealed = crate::sync::keys::seal_for_recipient(new_key, &recipient, vault_id, epoch)?;
        packages.push(identity.sign_key_package(KeyPackageV3 {
            vault_id: vault_id.to_string(),
            sender_device_id: identity.device_id.clone(),
            recipient_device_id: member.device_id.clone(),
            vault_epoch: epoch,
            entry_digest: entry_digest.to_string(),
            ciphertext: URL_SAFE_NO_PAD.encode(sealed),
            signature: String::new(),
        }));
    }
    Ok(packages)
}

fn refused_before_commit(error: &crate::sync::client::SyncError) -> bool {
    use crate::sync::client::SyncError;
    !matches!(error, SyncError::Unavailable(_) | SyncError::Failed(_))
}

async fn rekey_without(
    app: &AppHandle,
    vault: &tauri::State<'_, VaultState>,
    subject: &str,
    master_password: &str,
    adopt_locally: bool,
) -> Result<Option<String>, String> {
    let client = SyncClient::connect(app).await?;
    let identity = this_identity(app)?;
    require_no_pending_key_change(app)?;
    let local = load_state(app)?.ok_or("Set up Sesame Sync on this device first.")?;
    let refreshed = refresh(&client, &local).await?;
    require_activated(&refreshed)?;
    let list = &refreshed.update.list;
    if list
        .member(subject)
        .is_none_or(|member| member.removed_index != 0)
    {
        return Err("That device is not part of this vault.".into());
    }
    {
        let session = vault
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session
            .as_ref()
            .ok_or("Unlock Sesame before removing a device.")?;
        verify_master_password(unlocked, master_password)?;
        if vault_id_of(unlocked)? != local.vault_id {
            return Err("The unlocked vault is not the Sync vault.".into());
        }
    }
    let entry = remove_entry(&identity, list, subject).map_err(present_proof)?;
    let mut new_key = [0u8; 32];
    crate::vault::util::fill_secret(&mut new_key)?;
    let excluded = [subject, identity.device_id.as_str()];
    let packages = survivor_packages(
        &identity,
        list,
        &local.vault_id,
        &new_key,
        &excluded,
        entry.epoch_after,
        &entry.digest(),
    )?;
    let journal_path = journal_file(app)?;
    if adopt_locally {
        let saved =
            Journal::new(&entry, list.head_digest(), &new_key, unix_now()).save(&journal_path);
        if let Err(error) = saved {
            new_key.zeroize();
            return Err(error);
        }
    }
    if let Err(error) = client.remove(&identity, &entry, &packages).await {
        if adopt_locally && refused_before_commit(&error) {
            let _ = rekey_journal::forget(&journal_path);
        }
        new_key.zeroize();
        return Err(present(error));
    }

    let mut entries = refreshed.update.entries.clone();
    entries.push(entry.clone());
    let mut next = local.clone();
    next.entries = entries;
    let recovery_kit = if adopt_locally {
        let kit = {
            let mut session = vault
                .session
                .lock()
                .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
            let unlocked = session
                .as_mut()
                .ok_or("Unlock Sesame before removing a device.")?;
            let payload = unlocked.open_payload()?.clone();
            let kit = adopt(unlocked, new_key, payload, master_password)?;
            vault.advance_session_epoch();
            kit
        };
        vault.cache_pin_unlock(false);
        vault.cache_hello_unlock(false);
        crate::commands::lifecycle::discard_pin_throttle_state(app, vault);
        crate::browser_fill::cancel_pending_approvals(app);
        next.activated_epoch = entry.epoch_after;
        Some(kit)
    } else {
        None
    };
    new_key.zeroize();
    if adopt_locally {
        save_state(app, &next)?;
        let _ = rekey_journal::forget(&journal_path);
    }
    Ok(recovery_kit)
}

#[tauri::command]
pub async fn sync_remove_device(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    device_id: String,
    master_password: String,
) -> Result<SyncRemovalResult, String> {
    let identity = this_identity(&app)?;
    if device_id == identity.device_id {
        return Err("Turn Sesame Sync off on this device instead of removing it.".into());
    }
    let kit = rekey_without(&app, &state, &device_id, &master_password, true)
        .await?
        .ok_or("Sesame could not finish the removal.")?;
    Ok(SyncRemovalResult { recovery_kit: kit })
}

pub(super) async fn leave_vault(
    app: &AppHandle,
    state: &tauri::State<'_, VaultState>,
    master_password: &str,
) -> Result<(), String> {
    let identity = this_identity(app)?;
    rekey_without(app, state, &identity.device_id, master_password, false)
        .await
        .map(|_| ())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncConflictSideView {
    pub device_label: String,
    pub revision: i64,
    pub changed_at: String,
    pub entry_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncConflictView {
    pub this_device: SyncConflictSideView,
    pub other_device: SyncConflictSideView,
}

fn sender_label(
    unlocked: &crate::vault::UnlockedVault,
    local: &SyncState,
    list: &DeviceList,
    device_id: &str,
) -> String {
    list.member(device_id)
        .and_then(|member| {
            unlocked
                .expose_vault_key(|key| {
                    Ok(open_label(
                        key,
                        &local.vault_id,
                        &member.device_id,
                        &member.sealed_label,
                    ))
                })
                .ok()
                .flatten()
        })
        .unwrap_or_else(|| "Another device".to_string())
}

#[tauri::command]
pub async fn sync_conflict_details(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<SyncConflictView, String> {
    let client = SyncClient::connect(&app).await?;
    let local = load_state(&app)?.ok_or("Set up Sesame Sync on this device first.")?;
    let remote = fetch_remote(&client, &local).await?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
    let unlocked = session.as_ref().ok_or("Unlock Sesame before syncing.")?;
    let local_payload = unlocked.open_payload()?;
    let authenticated =
        unlocked.expose_vault_key(|key| decrypt_remote(key, &remote.header, &remote.ciphertext))?;
    let label = sender_label(
        unlocked,
        &local,
        &remote.refreshed.update.list,
        &remote.header.device_id,
    );
    Ok(SyncConflictView {
        this_device: SyncConflictSideView {
            device_label: "This device".to_string(),
            revision: signed_revision(local.head_revision()),
            changed_at: String::new(),
            entry_count: local_payload.entries.len(),
        },
        other_device: SyncConflictSideView {
            device_label: label,
            revision: signed_revision(remote.header.revision),
            changed_at: remote.accepted_at.clone(),
            entry_count: authenticated.payload().entries.len(),
        },
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResolutionResult {
    pub revision: i64,
    pub vault_epoch: i64,
    pub entry_count: usize,
    pub recovery_copies: Vec<String>,
    pub removed_old_copies: usize,
}

#[tauri::command]
pub async fn sync_resolve_conflict(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
    keep: String,
) -> Result<SyncResolutionResult, String> {
    let _run = coordinator
        .begin_manual()
        .ok_or_else(|| ALREADY_SYNCING.to_string())?;
    let resolved = resolve_conflict(app, state, keep).await?;
    coordinator.resume();
    Ok(resolved)
}

async fn resolve_conflict(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    keep: String,
) -> Result<SyncResolutionResult, String> {
    let keep_this = match keep.as_str() {
        "this" => true,
        "other" => false,
        _ => return Err("Choose which vault to keep.".into()),
    };
    require_no_pending_key_change(&app)?;
    let client = SyncClient::connect(&app).await?;
    let local = load_state(&app)?.ok_or("Set up Sesame Sync on this device first.")?;
    let remote = fetch_remote(&client, &local).await?;
    require_activated(&remote.refreshed)?;
    let data_dir = local_data_dir(&app)?;

    let (
        local_plaintext,
        remote_authenticated,
        local_entries,
        remote_entries,
        recovery_copies,
        removed_old_copies,
    ) = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session.as_ref().ok_or("Unlock Sesame before syncing.")?;
        let (local_bytes, local_count) = local_payload_bytes(unlocked)?;
        let decrypted = unlocked
            .expose_vault_key(|key| decrypt_remote(key, &remote.header, &remote.ciphertext))?;
        let remote_count = decrypted.payload().entries.len();
        let directory = crate::sync::conflict_backup::backup_dir(&data_dir);
        let stamp = backup_stamp();
        let mut written = Vec::with_capacity(2);
        for (side, revision, payload) in [
            (
                crate::sync::conflict_backup::Side::ThisDevice,
                signed_revision(local.head_revision()),
                local_bytes.as_slice(),
            ),
            (
                crate::sync::conflict_backup::Side::OtherDevice,
                signed_revision(remote.header.revision),
                decrypted.bytes(),
            ),
        ] {
            written.push(crate::sync::conflict_backup::write_verified(
                &directory, unlocked, side, revision, payload, &stamp,
            )?);
        }
        let removed_old_copies =
            crate::sync::conflict_backup::prune_and_report(&app, &directory, &written);
        let names: Vec<String> = written
            .into_iter()
            .map(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        (
            local_bytes,
            decrypted,
            local_count,
            remote_count,
            names,
            removed_old_copies,
        )
    };
    let captured = payload_digest(&local_plaintext);

    if keep_this {
        let upload_base = {
            let mut base = local.clone();
            base.head = Some(remote.header.clone());
            base
        };
        {
            let session = state
                .session
                .lock()
                .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
            let unlocked = session.as_ref().ok_or("Unlock Sesame before syncing.")?;
            confirm_unchanged(unlocked, &captured)?;
        }
        let result = upload_on(
            &app,
            &state,
            Some(remote.header.clone()),
            &upload_base,
            &client,
            remote.refreshed,
        )
        .await?;
        return Ok(SyncResolutionResult {
            revision: result.revision,
            vault_epoch: result.vault_epoch,
            entry_count: local_entries,
            recovery_copies,
            removed_old_copies,
        });
    }

    let payload = remote_authenticated.payload().clone();
    let applied_digest = payload_digest(
        &serde_json::to_vec(&payload)
            .map_err(|_| "Sesame could not read the synced vault.".to_string())?,
    );
    {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session.as_mut().ok_or("Unlock Sesame before syncing.")?;
        confirm_unchanged(unlocked, &captured)?;
        crate::vault::storage::commit_payload_change(unlocked, payload)?;
        state.advance_session_epoch();
    }
    crate::browser_fill::cancel_pending_approvals(&app);
    let mut next = local;
    next.entries = remote.refreshed.update.entries;
    next.head = Some(remote.header.clone());
    next.payload_digest = applied_digest;
    next.receipt = remote.refreshed.update.receipt;
    save_state(&app, &next)?;
    Ok(SyncResolutionResult {
        revision: signed_revision(remote.header.revision),
        vault_epoch: signed_revision(remote.header.vault_epoch),
        entry_count: remote_entries,
        recovery_copies,
        removed_old_copies,
    })
}

fn confirm_unchanged(vault: &crate::vault::UnlockedVault, captured: &str) -> Result<(), String> {
    let (now, _) = local_payload_bytes(vault)?;
    if payload_digest(&now) != captured {
        return Err("This vault changed while you were deciding. Open Sesame Sync and resolve the difference again.".into());
    }
    Ok(())
}

fn backup_stamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    format!("{seconds}")
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
}

#[tauri::command]
pub async fn sync_coordinator_status(
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
) -> Result<SyncCoordinatorView, String> {
    use crate::sync::coordinator::{Halt, Phase};

    let status = coordinator.status();
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
    };
    Ok(SyncCoordinatorView {
        phase: phase.to_string(),
        halt: halt.to_string(),
        conflict_revision,
        pending: status.pending,
        last_success_revision: status.last_success_revision.unwrap_or(0),
        consecutive_failures: status.consecutive_failures,
    })
}

#[tauri::command]
pub async fn sync_now(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
    manual: Option<bool>,
) -> Result<SyncCoordinatorView, String> {
    if manual.unwrap_or(false) {
        coordinator.retry_after_user_action();
    }
    if !coordinator.begin() {
        return sync_coordinator_status(coordinator).await;
    }
    let outcome = match run_one_transfer(&app, &state).await {
        Ok(outcome) => outcome,
        Err(message) => classify_transfer_failure(&message),
    };
    coordinator.finish(outcome);
    sync_coordinator_status(coordinator).await
}

async fn run_one_transfer(
    app: &AppHandle,
    state: &tauri::State<'_, VaultState>,
) -> Result<crate::sync::coordinator::Outcome, String> {
    use crate::sync::coordinator::Outcome;

    let Some(local) = load_state(app)? else {
        return Ok(Outcome::AlreadyCurrent);
    };
    let client = SyncClient::connect(app).await?;
    let local = reconcile_pending_upload(app, &client, local).await?;
    let server = client.state().await.map_err(present)?;
    let has_local_changes = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session.as_ref().ok_or("sync_locked")?;
        let (plaintext, _) = local_payload_bytes(unlocked)?;
        local.has_local_changes(&plaintext)
    };
    if has_local_changes {
        let result = upload_vault(app.clone(), state.clone()).await?;
        return Ok(Outcome::Uploaded {
            revision: result.revision,
        });
    }
    if server.current_revision > local.head_revision() {
        let result = download_vault(app.clone(), state.clone()).await?;
        return Ok(Outcome::Downloaded {
            revision: result.revision,
        });
    }
    let refreshed = refresh(&client, &local).await?;
    record_checkpoint_if_due(app, &client, &local, &refreshed).await;
    Ok(Outcome::AlreadyCurrent)
}

include!("sync_transfer_recovery.rs");
include!("sync_transfer_coordinator.rs");

#[cfg(test)]
mod survivor_tests {
    use super::*;
    use crate::sync::engine::{add_entry, create_entry, seal_label, NewDevice};
    use crate::sync::identity::DeviceIdentity;

    const VAULT: &str = "vaultAAAAAAAAAAAA01";

    fn identity(hybrid: bool) -> DeviceIdentity {
        let generated = DeviceIdentity::generate().expect("identity");
        if hybrid {
            generated
        } else {
            generated.without_hybrid_key()
        }
    }

    fn mixed_vault(
        creator: &DeviceIdentity,
        joiners: &[&DeviceIdentity],
    ) -> (DeviceList, crate::sync::devicelist::DeviceListEntry) {
        let label = |device: &DeviceIdentity| {
            seal_label(&[9u8; 32], VAULT, &device.device_id, "Device").expect("label")
        };
        let mut entries = vec![create_entry(creator, VAULT, &label(creator))];
        let mut list = DeviceList::verify(&entries).expect("list");
        for joiner in joiners {
            let entry = add_entry(
                creator,
                &list,
                &NewDevice {
                    device_id: &joiner.device_id,
                    signing_key: &URL_SAFE_NO_PAD.encode(joiner.signing_public_key()),
                    package_key: &URL_SAFE_NO_PAD.encode(joiner.package_public_key()),
                },
                &label(joiner),
                0,
            )
            .expect("add");
            list.extend(&entry).expect("extend");
            entries.push(entry);
        }
        let removal =
            remove_entry(creator, &list, &joiners[joiners.len() - 1].device_id).expect("removal");
        (list, removal)
    }

    fn package_for<'a>(
        packages: &'a [KeyPackageV3],
        device: &DeviceIdentity,
    ) -> Option<&'a KeyPackageV3> {
        packages
            .iter()
            .find(|package| package.recipient_device_id == device.device_id)
    }

    #[test]
    fn a_rekey_seals_the_suite_each_survivor_advertises_and_nothing_to_the_removed_device() {
        let creator = identity(true);
        let older = identity(false);
        let newer = identity(true);
        let removed = identity(true);
        let (list, removal) = mixed_vault(&creator, &[&older, &newer, &removed]);
        let new_key = [4u8; 32];
        let excluded = [removed.device_id.as_str(), creator.device_id.as_str()];

        let packages = survivor_packages(
            &creator,
            &list,
            VAULT,
            &new_key,
            &excluded,
            removal.epoch_after,
            &removal.digest(),
        )
        .expect("packages");

        assert_eq!(packages.len(), 2);
        assert!(package_for(&packages, &removed).is_none());
        assert!(package_for(&packages, &creator).is_none());
        let sealed = |device: &DeviceIdentity| {
            let package = package_for(&packages, device).expect("package");
            assert_eq!(package.sender_device_id, creator.device_id);
            assert_eq!(package.vault_epoch, removal.epoch_after);
            assert_eq!(package.entry_digest, removal.digest());
            assert!(package
                .verify(&URL_SAFE_NO_PAD.encode(creator.signing_public_key()))
                .is_ok());
            URL_SAFE_NO_PAD.decode(&package.ciphertext).expect("bytes")
        };

        let for_older = sealed(&older);
        let for_newer = sealed(&newer);
        assert_eq!(
            for_older.len(),
            crate::sync::keys::X25519_KEY_BYTES
                + crate::sync::keys::KEY_PACKAGE_NONCE_BYTES
                + new_key.len()
                + 16
        );
        assert_eq!(for_newer[0], crate::sync::keys::HYBRID_PACKAGE_VERSION);
        assert!(for_newer.len() > for_older.len());

        assert_eq!(
            older
                .open_key_package(&for_older, VAULT, removal.epoch_after)
                .expect("older opens"),
            new_key
        );
        assert_eq!(
            newer
                .open_key_package(&for_newer, VAULT, removal.epoch_after)
                .expect("newer opens"),
            new_key
        );
        assert!(older
            .open_key_package(&for_newer, VAULT, removal.epoch_after)
            .is_err());
        assert!(newer
            .open_key_package(&for_older, VAULT, removal.epoch_after)
            .is_err());
        assert!(newer
            .open_key_package(&for_newer, VAULT, removal.epoch_after + 1)
            .is_err());
        assert!(newer
            .open_key_package(&for_newer, "vaultBBBBBBBBBBBB02", removal.epoch_after)
            .is_err());
        assert!(removed
            .open_key_package(&for_newer, VAULT, removal.epoch_after)
            .is_err());
    }

    #[test]
    fn a_rekey_to_a_vault_of_older_devices_seals_only_the_older_suite() {
        let creator = identity(false);
        let first = identity(false);
        let removed = identity(false);
        let (list, removal) = mixed_vault(&creator, &[&first, &removed]);
        let packages = survivor_packages(
            &creator,
            &list,
            VAULT,
            &[4u8; 32],
            &[removed.device_id.as_str(), creator.device_id.as_str()],
            removal.epoch_after,
            &removal.digest(),
        )
        .expect("packages");
        assert_eq!(packages.len(), 1);
        let bytes = URL_SAFE_NO_PAD
            .decode(&packages[0].ciphertext)
            .expect("bytes");
        assert!(bytes.len() < 512);
        assert_eq!(
            first
                .open_key_package(&bytes, VAULT, removal.epoch_after)
                .expect("opens"),
            [4u8; 32]
        );
    }
}

#[cfg(test)]
mod key_change_tests {
    use super::*;
    use crate::sync::client::SyncError;
    use crate::sync::devicelist::DeviceListEntry;
    use crate::sync::engine::{add_entry, create_entry, seal_label, NewDevice};
    use crate::sync::identity::DeviceIdentity;

    const VAULT: &str = "vaultAAAAAAAAAAAA01";

    fn lists() -> (DeviceListEntry, DeviceList, DeviceList) {
        let creator = DeviceIdentity::generate().expect("identity");
        let other = DeviceIdentity::generate().expect("identity");
        let label = |device: &DeviceIdentity| {
            seal_label(&[9u8; 32], VAULT, &device.device_id, "Device").expect("label")
        };
        let mut base =
            DeviceList::verify(&[create_entry(&creator, VAULT, &label(&creator))]).expect("list");
        let add = add_entry(
            &creator,
            &base,
            &NewDevice {
                device_id: &other.device_id,
                signing_key: &URL_SAFE_NO_PAD.encode(other.signing_public_key()),
                package_key: &URL_SAFE_NO_PAD.encode(other.package_public_key()),
            },
            &label(&other),
            0,
        )
        .expect("add");
        base.extend(&add).expect("extend");
        let removal = remove_entry(&creator, &base, &other.device_id).expect("removal");
        let mut committed = base.clone();
        committed.extend(&removal).expect("extend");
        (removal, base, committed)
    }

    fn path(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sesame-keychange-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        rekey_journal::journal_path(&dir)
    }

    #[test]
    fn without_a_journal_nothing_changes() {
        let (_, base, _) = lists();
        let path = path("none");
        assert!(matches!(
            reconcile_key_change(&path, &base, 1),
            Ok(KeyChange::Proceed)
        ));
    }

    #[test]
    fn a_removal_in_the_list_hands_back_the_saved_key_and_keeps_the_journal_until_adoption() {
        let (removal, base, committed) = lists();
        let path = path("adopt");
        Journal::new(&removal, base.head_digest(), &[4u8; 32], 1)
            .save(&path)
            .expect("saved");
        match reconcile_key_change(&path, &committed, 2) {
            Ok(KeyChange::Adopt(journal)) => assert_eq!(journal.key(), [4u8; 32]),
            _ => panic!("expected the saved key"),
        }
        assert!(rekey_journal::is_pending(&path));
    }

    #[test]
    fn a_removal_that_did_not_commit_drops_the_journal_and_says_nothing_changed() {
        let (removal, base, _) = lists();
        let path = path("not-done");
        Journal::new(&removal, base.head_digest(), &[4u8; 32], 1)
            .save(&path)
            .expect("saved");
        assert!(matches!(
            reconcile_key_change(&path, &base, 1),
            Ok(KeyChange::NotDone)
        ));
        assert!(!rekey_journal::is_pending(&path));
    }

    #[test]
    fn a_journal_that_matches_nothing_drops_and_leaves_the_normal_path_to_a_device_that_is_behind()
    {
        let (removal, base, _) = lists();
        let path = path("stale");
        Journal::new(&removal, base.head_digest(), &[4u8; 32], 1)
            .save(&path)
            .expect("saved");
        assert!(matches!(
            reconcile_key_change(&path, &base, 0),
            Ok(KeyChange::Proceed)
        ));
        assert!(!rekey_journal::is_pending(&path));
    }

    #[test]
    fn an_unreadable_journal_is_kept_and_reported() {
        let (_, base, _) = lists();
        let path = path("unreadable");
        std::fs::write(&path, b"damaged").unwrap();
        let error = match reconcile_key_change(&path, &base, 1) {
            Err(error) => error,
            Ok(_) => panic!("a damaged journal was accepted"),
        };
        assert!(error.contains("pair it again"));
        assert!(rekey_journal::is_pending(&path));
    }

    #[test]
    fn only_an_answer_the_service_could_not_have_committed_drops_the_journal() {
        for refused in [
            SyncError::Conflict,
            SyncError::NotApproved,
            SyncError::NotActivated,
            SyncError::NotEntitled,
            SyncError::NotFound,
            SyncError::StorageFull,
        ] {
            assert!(refused_before_commit(&refused), "{refused:?}");
        }
        for unknown in [
            SyncError::Unavailable("offline".into()),
            SyncError::Failed("timed out".into()),
        ] {
            assert!(!refused_before_commit(&unknown), "{unknown:?}");
        }
    }
}
