use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use zeroize::Zeroize;

use crate::application::sync::{
    local_payload_bytes, present, present_proof, refresh, require_activated, signed_revision,
    transfer_result, unix_now, vault_id_of, verify_master_password, Refreshed, SyncStore,
    SyncTransferResult, NOT_ACTIVATED,
};
use crate::application::sync_adopt::{adopt, adopt_with, digest_after_commit, KeptThroughAdoption};
use crate::application::sync_recovery::backup_stamp;
use crate::application::DesktopEffects;
use crate::sync::client::{SyncClient, SyncError};
use crate::sync::devicelist::DeviceList;
use crate::sync::engine::{
    build_header, open_label, plan_header, remove_entry, rotate_entry, verify_accepted,
};
use crate::sync::header::Header;
use crate::sync::key_change::PreparedKeyChange;
use crate::sync::rekey_journal::{self, Journal, Outcome};
use crate::sync::request::KeyPackageV3;
use crate::sync::state::{payload_digest, SyncState};
use crate::vault::{VaultPayload, VaultResult, VaultState};

const SEAL_OVERHEAD_BYTES: usize = 16;

fn decode_bytes(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "A Sync value is not valid base64.".to_string())
}

fn persist(
    store: &SyncStore,
    mut state: SyncState,
    refreshed_entries: Vec<crate::sync::devicelist::DeviceListEntry>,
) -> VaultResult<SyncState> {
    state.entries = refreshed_entries;
    store.save_state(&state)?;
    Ok(state)
}

pub(crate) async fn upload_on_in_state(
    state: &VaultState,
    store: &SyncStore,
    previous: Option<Header>,
    base: &SyncState,
    client: &SyncClient,
    refreshed: Refreshed,
) -> Result<SyncTransferResult, String> {
    let identity = store.this_identity()?;
    let list = refreshed.update.list;
    let plan = plan_header(&identity.device_id, &list, previous.as_ref()).map_err(present_proof)?;
    let aad = plan.aad();
    let (blob, entry_count, plaintext_digest) = {
        let session = state
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
    store.save_state(&staged)?;
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
    store.save_state(&next)?;
    Ok(transfer_result(
        header.revision,
        header.vault_epoch,
        entry_count,
    ))
}

/// An earlier upload may have reached the service while its answer was lost or the app stopped.
/// This settles that before anything is compared, so the upload is not mistaken for a conflict.
pub(crate) async fn reconcile_pending_upload_in_state(
    store: &SyncStore,
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
        store.save_state(&next)?;
        return Ok(next);
    }
    let mut next = local;
    next.pending_upload = None;
    next.entries = refreshed.update.entries;
    store.save_state(&next)?;
    Ok(next)
}

pub(crate) async fn upload_vault_in_state(
    state: &VaultState,
    store: &SyncStore,
    client: &SyncClient,
) -> Result<SyncTransferResult, String> {
    store.require_no_pending_key_change()?;
    let local = store
        .load_state()?
        .ok_or("Set up Sesame Sync on this device first.")?;
    let local = reconcile_pending_upload_in_state(store, client, local).await?;
    let refreshed = refresh(client, &local).await?;
    require_activated(&refreshed)?;
    match crate::sync::state::decide_upload(
        local.head_revision(),
        refreshed.server.current_revision,
    ) {
        crate::sync::state::UploadDecision::Offer { .. } => {}
        crate::sync::state::UploadDecision::Conflict { server_revision } => {
            persist(store, local, refreshed.update.entries)?;
            return Err(format!("sync_conflict:{server_revision}"));
        }
    }
    let previous = local.head.clone();
    upload_on_in_state(state, store, previous, &local, client, refreshed).await
}

pub(crate) fn decrypt_remote(
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

pub(crate) fn apply_remote_payload(
    unlocked: &mut crate::vault::UnlockedVault,
    payload: VaultPayload,
) -> Result<(String, usize), String> {
    let entries = payload.entries.len();
    let digest = digest_after_commit(&payload)?;
    crate::vault::storage::commit_payload_change(unlocked, payload)?;
    Ok((digest, entries))
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

pub(crate) async fn download_vault_in_state(
    state: &VaultState,
    store: &SyncStore,
    client: &SyncClient,
    effects: &dyn DesktopEffects,
) -> Result<SyncTransferResult, String> {
    store.require_no_pending_key_change()?;
    let local = store
        .load_state()?
        .ok_or("Set up Sesame Sync on this device first.")?;
    let remote = fetch_remote(client, &local).await?;
    require_activated(&remote.refreshed)?;
    let current_revision = local.head_revision();
    if remote.header.revision <= current_revision && local.head.is_some() {
        persist(store, local, remote.refreshed.update.entries)?;
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
        let applied = apply_remote_payload(unlocked, authenticated.payload().clone())?;
        state.advance_session_epoch();
        applied
    };
    effects.cancel_pending_approvals();
    let mut next = local;
    next.entries = remote.refreshed.update.entries;
    next.head = Some(remote.header.clone());
    next.payload_digest = applied_digest;
    next.receipt = remote.refreshed.update.receipt;
    store.save_state(&next)?;
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

pub(crate) async fn take_new_key_in_state(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
    client: &SyncClient,
    master_password: String,
) -> Result<SyncTakeKeyResult, String> {
    let identity = store.this_identity()?;
    let local = store
        .load_state()?
        .ok_or("Set up Sesame Sync on this device first.")?;
    let refreshed = refresh(client, &local).await?;
    if refreshed.server.device_state != "approved" {
        return Err("This device is not approved to sync.".into());
    }
    let list = &refreshed.update.list;
    let epoch = list.epoch();
    match reconcile_key_change(
        &store.journal_path(),
        list,
        refreshed.server.activated_epoch,
    )? {
        KeyChange::Adopt(journal) => {
            return adopt_journal_key_in_state(
                state,
                store,
                effects,
                local,
                refreshed,
                &journal,
                &master_password,
            )
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
    let (recovery_kit, kept) = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session
            .as_mut()
            .ok_or("Unlock Sesame before taking the new key.")?;
        verify_master_password(unlocked, &master_password)?;
        let kept = KeptThroughAdoption::capture(&local, list, unlocked)?;
        let payload = unlocked.open_payload()?.clone();
        let kit = adopt(unlocked, key, payload, &master_password)?;
        state.advance_session_epoch();
        (kit, kept)
    };
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    effects.discard_pin_throttle_state(state);
    effects.cancel_pending_approvals();
    client
        .activate(&identity, &package.digest())
        .await
        .map_err(present)?;
    let mut next = local;
    next.entries = refreshed.update.entries;
    next.activated_epoch = epoch;
    kept.apply(&mut next);
    store.save_state(&next)?;
    Ok(SyncTakeKeyResult { recovery_kit })
}

pub(crate) const KEY_CHANGE_NOT_DONE: &str = "The vault key change did not go through, so nothing changed. Remove the device again if you still want to.";

pub(crate) enum KeyChange {
    Adopt(Journal),
    NotDone,
    Proceed,
}

pub(crate) fn reconcile_key_change(
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

pub(crate) async fn adopt_journal_key_in_state(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
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
            let kept = KeptThroughAdoption::capture(&local, &refreshed.update.list, unlocked)?;
            let payload = unlocked.open_payload()?.clone();
            let kit = adopt_with(
                unlocked,
                key,
                payload,
                master_password,
                journal.recovery.clone(),
            )?;
            state.advance_session_epoch();
            Ok((kit, kept))
        })
    };
    key.zeroize();
    let (kit, kept) = adopted?;
    let recovery_kit = kit.unwrap_or_default();
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    effects.discard_pin_throttle_state(state);
    effects.cancel_pending_approvals();
    let mut next = local;
    next.entries = refreshed.update.entries;
    next.activated_epoch = journal.epoch_after;
    kept.apply(&mut next);
    store.save_state(&next)?;
    rekey_journal::forget(&store.journal_path())?;
    Ok(SyncTakeKeyResult { recovery_kit })
}

pub(crate) fn survivor_packages(
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

pub(crate) fn every_member_has_the_newer_key(list: &DeviceList) -> bool {
    list.current()
        .iter()
        .all(|member| crate::application::sync::is_newer_key(&member.package_key))
}

pub(crate) fn refused_before_commit(error: &SyncError) -> bool {
    !matches!(error, SyncError::Unavailable(_) | SyncError::Failed(_))
}

pub(crate) struct RekeyRequest<'a> {
    pub(crate) prepared: &'a PreparedKeyChange,
    pub(crate) subject: Option<&'a str>,
    pub(crate) master_password: &'a str,
    pub(crate) adopt_locally: bool,
}

pub(crate) async fn rekey_without_in_state(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
    client: &SyncClient,
    request: RekeyRequest<'_>,
) -> Result<(), String> {
    let RekeyRequest {
        prepared,
        subject,
        master_password,
        adopt_locally,
    } = request;
    let identity = store.this_identity()?;
    store.require_no_pending_key_change()?;
    let local = store
        .load_state()?
        .ok_or("Set up Sesame Sync on this device first.")?;
    let refreshed = refresh(client, &local).await?;
    require_activated(&refreshed)?;
    let list = &refreshed.update.list;
    if let Some(subject) = subject {
        if list
            .member(subject)
            .is_none_or(|member| member.removed_index != 0)
        {
            return Err("That device is not part of this vault.".into());
        }
    } else if !every_member_has_the_newer_key(list) {
        return Err(
            "Every device must have the newer key before the vault key can be changed.".into(),
        );
    }
    {
        let session = state
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
    let entry = match subject {
        Some(subject) => remove_entry(&identity, list, subject),
        None => rotate_entry(&identity, list),
    }
    .map_err(present_proof)?;
    let mut new_key = [0u8; 32];
    let recovery = if adopt_locally {
        let (key, recovery) = prepared.take(std::time::Instant::now())?;
        new_key = key;
        Some(recovery)
    } else {
        crate::vault::util::fill_secret(&mut new_key)?;
        None
    };
    let excluded: Vec<&str> = subject
        .into_iter()
        .chain(std::iter::once(identity.device_id.as_str()))
        .collect();
    let packages = survivor_packages(
        &identity,
        list,
        &local.vault_id,
        &new_key,
        &excluded,
        entry.epoch_after,
        &entry.digest(),
    )?;
    let journal_path = store.journal_path();
    if adopt_locally {
        let saved = recovery
            .clone()
            .ok_or_else(|| "Sesame could not prepare the new recovery kit.".to_string())
            .and_then(|recovery| {
                Journal::new(&entry, list.head_digest(), &new_key, recovery, unix_now())
                    .save(&journal_path)
            });
        if let Err(error) = saved {
            new_key.zeroize();
            return Err(error);
        }
    }
    let posted = match subject {
        Some(_) => client.remove(&identity, &entry, &packages).await,
        None => client.rotate(&identity, &entry, &packages).await,
    };
    if let Err(error) = posted {
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
    if adopt_locally {
        {
            let mut session = state
                .session
                .lock()
                .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
            let unlocked = session
                .as_mut()
                .ok_or("Unlock Sesame before removing a device.")?;
            let kept = KeptThroughAdoption::capture(&local, list, unlocked)?;
            let payload = unlocked.open_payload()?.clone();
            adopt_with(unlocked, new_key, payload, master_password, recovery)?;
            state.advance_session_epoch();
            kept.apply(&mut next);
        }
        state.cache_pin_unlock(false);
        state.cache_hello_unlock(false);
        effects.discard_pin_throttle_state(state);
        effects.cancel_pending_approvals();
        next.activated_epoch = entry.epoch_after;
    }
    new_key.zeroize();
    if adopt_locally {
        store.save_state(&next)?;
        let _ = rekey_journal::forget(&journal_path);
    }
    Ok(())
}

pub(crate) async fn leave_vault_in_state(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
    client: &SyncClient,
    own_device_id: &str,
    master_password: &str,
) -> Result<(), String> {
    rekey_without_in_state(
        state,
        store,
        effects,
        client,
        RekeyRequest {
            prepared: &PreparedKeyChange::default(),
            subject: Some(own_device_id),
            master_password,
            adopt_locally: false,
        },
    )
    .await
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

pub(crate) async fn sync_conflict_details_in_state(
    state: &VaultState,
    store: &SyncStore,
    client: &SyncClient,
) -> Result<SyncConflictView, String> {
    let local = store
        .load_state()?
        .ok_or("Set up Sesame Sync on this device first.")?;
    let remote = fetch_remote(client, &local).await?;
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

pub(crate) fn conflict_choice(keep: &str) -> Result<bool, String> {
    match keep {
        "this" => Ok(true),
        "other" => Ok(false),
        _ => Err("Choose which vault to keep.".into()),
    }
}

pub(crate) async fn resolve_conflict_in_state(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
    client: &SyncClient,
    keep: String,
) -> Result<SyncResolutionResult, String> {
    let keep_this = conflict_choice(&keep)?;
    store.require_no_pending_key_change()?;
    let local = store
        .load_state()?
        .ok_or("Set up Sesame Sync on this device first.")?;
    let remote = fetch_remote(client, &local).await?;
    require_activated(&remote.refreshed)?;
    let data_dir = store.backup_dir();

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
        let directory = data_dir;
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
            crate::application::sync_recovery::prune_and_report(effects, &directory, &written);
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
        let result = upload_on_in_state(
            state,
            store,
            Some(remote.header.clone()),
            &upload_base,
            client,
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

    let applied_digest = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session.as_mut().ok_or("Unlock Sesame before syncing.")?;
        confirm_unchanged(unlocked, &captured)?;
        let (digest, _) = apply_remote_payload(unlocked, remote_authenticated.payload().clone())?;
        state.advance_session_epoch();
        digest
    };
    effects.cancel_pending_approvals();
    let mut next = local;
    next.entries = remote.refreshed.update.entries;
    next.head = Some(remote.header.clone());
    next.payload_digest = applied_digest;
    next.receipt = remote.refreshed.update.receipt;
    store.save_state(&next)?;
    Ok(SyncResolutionResult {
        revision: signed_revision(remote.header.revision),
        vault_epoch: signed_revision(remote.header.vault_epoch),
        entry_count: remote_entries,
        recovery_copies,
        removed_old_copies,
    })
}

pub(crate) fn confirm_unchanged(
    vault: &crate::vault::UnlockedVault,
    captured: &str,
) -> Result<(), String> {
    let (now, _) = local_payload_bytes(vault)?;
    if payload_digest(&now) != captured {
        return Err("This vault changed while you were deciding. Open Sesame Sync and resolve the difference again.".into());
    }
    Ok(())
}

pub(crate) fn classify_transfer_failure(message: &str) -> crate::sync::coordinator::Outcome {
    use crate::sync::coordinator::{Halt, Outcome};

    if message == crate::sync::floor::REFUSAL {
        return Outcome::Halt(Halt::Incompatible);
    }
    if message == crate::sync::floor::DAMAGED_REFUSAL {
        return Outcome::Halt(Halt::FloorDamaged);
    }
    if let Some(revision) = message.strip_prefix("sync_conflict:") {
        return Outcome::Halt(Halt::Conflict {
            server_revision: revision.parse().unwrap_or(0),
        });
    }
    if message == NOT_ACTIVATED {
        return Outcome::Halt(Halt::NeedsNewKey);
    }
    if message == "sync_locked" || message.contains("Unlock Sesame") {
        return Outcome::Halt(Halt::Locked);
    }
    if message.starts_with("sync_fork:") {
        return Outcome::Halt(Halt::Fork);
    }
    if message.contains("not approved") || message.contains("no longer") {
        return Outcome::Halt(Halt::Revoked);
    }
    if message.starts_with("sync_not_entitled:") {
        return Outcome::Halt(Halt::NotEntitled);
    }
    if message.contains("does not match the expected format") || message.contains("version") {
        return Outcome::Halt(Halt::Incompatible);
    }
    Outcome::Transient
}

pub(crate) async fn record_checkpoint_if_due_in_state(
    store: &SyncStore,
    client: &SyncClient,
    local: &SyncState,
    refreshed: &Refreshed,
) {
    if refreshed.server.device_state != "approved"
        || refreshed.server.activated_epoch != refreshed.server.vault_epoch
        || store.require_no_pending_key_change().is_err()
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
    let Ok(identity) = store.this_identity() else {
        return;
    };
    let checkpoint = identity.sign_checkpoint(crate::sync::checkpoint::Checkpoint::observe(
        list,
        head,
        &local.device_id,
        now,
    ));
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
    let _ = store.save_state(&next);
}

pub(crate) async fn run_one_transfer_in_state<Reconnect, Connecting>(
    state: &VaultState,
    store: &SyncStore,
    client: &SyncClient,
    effects: &dyn DesktopEffects,
    local: SyncState,
    reconnect: Reconnect,
) -> Result<crate::sync::coordinator::Outcome, String>
where
    Reconnect: Fn() -> Connecting,
    Connecting: std::future::Future<Output = Result<SyncClient, String>>,
{
    use crate::sync::coordinator::Outcome;

    let local = reconcile_pending_upload_in_state(store, client, local).await?;
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
        let transfer = reconnect().await?;
        let result = upload_vault_in_state(state, store, &transfer).await?;
        return Ok(Outcome::Uploaded {
            revision: result.revision,
        });
    }
    if server.current_revision > local.head_revision() {
        let transfer = reconnect().await?;
        let result = download_vault_in_state(state, store, &transfer, effects).await?;
        return Ok(Outcome::Downloaded {
            revision: result.revision,
        });
    }
    let refreshed = refresh(client, &local).await?;
    record_checkpoint_if_due_in_state(store, client, &local, &refreshed).await;
    Ok(Outcome::AlreadyCurrent)
}
