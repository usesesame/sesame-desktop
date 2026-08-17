//! Approval and vault transfer for Sync; compiled only under `sync-preview`.
//! The vault key never leaves this call graph and is never returned to the webview.

use serde::Serialize;
use tauri::AppHandle;
use zeroize::Zeroize;

use super::sync::{local_data_dir, present, SyncDeviceView};
use crate::sync::client::SyncClient;
use crate::vault::{VaultResult, VaultState};

use crate::sync::envelope::{snapshot_aad, snapshot_aad_for, snapshot_aad_for_draft};

fn this_identity(app: &AppHandle) -> VaultResult<crate::sync::identity::DeviceIdentity> {
    let path = crate::sync::identity::identity_path(&local_data_dir(app)?);
    crate::sync::identity::DeviceIdentity::load(&path)
        .map_err(|_| "Set up Sesame Sync on this device first.".to_string())
}

/// Seals the vault key to a device whose keys were frozen before fingerprint confirmation.
pub(super) async fn approve_frozen_device(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    vault_id: &str,
    expected_vault_epoch: i64,
    expected_session_epoch: u64,
    device_id: &str,
    frozen_signing_key: &str,
    frozen_encryption_key: &str,
) -> Result<SyncDeviceView, String> {
    let client = SyncClient::connect(&app)?;
    let identity = this_identity(&app)?;

    let current = client.download().await.map_err(present)?;
    if current.vault_id != vault_id {
        return Err("That approval was prepared for a different vault.".into());
    }
    if current.vault_epoch != expected_vault_epoch {
        return Err("That approval is no longer current. Compare the codes again.".into());
    }
    let recipient_key = decode_key(frozen_encryption_key)?;
    let device_id = device_id.to_string();

    // Lock released before await: holding a std::sync lock across an await can deadlock the vault.
    let sealed = {
        if state.session_epoch() != expected_session_epoch {
            return Err("That approval is no longer current. Compare the codes again.".into());
        }
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session
            .as_ref()
            .ok_or("Unlock Sesame before approving a device.")?;
        if vault.payload.vault_id.as_deref() != Some(vault_id) {
            return Err("That approval was prepared for a different vault.".into());
        }
        crate::sync::keys::seal_vault_key(vault.key.as_ref(), &recipient_key, &current.vault_id)?
    };

    let encoded = crate::sync::keys::encode_package(&sealed);
    let signature = identity.sign_key_package(&current.vault_id, &device_id, &encoded)?;
    let device = client
        .approve_device(
            &device_id,
            &identity.device_id,
            expected_vault_epoch,
            &encoded,
            &signature,
        )
        .await
        .map_err(present)?;
    Ok(SyncDeviceView {
        is_this_device: false,
        // The frozen keys, not this response's: the person never confirmed those.
        fingerprint: super::sync::approval_fingerprint(
            &current.vault_id,
            &device_id,
            frozen_signing_key,
            frozen_encryption_key,
        ),
        device_id: device.device_id,
        state: device.state,
        label: device.label,
        created_at: device.created_at,
        approved_at: device.approved_at,
        revoked_at: device.revoked_at,
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncTransferResult {
    pub revision: i64,
    pub vault_epoch: i64,
    pub entry_count: usize,
}

/// Encrypts and uploads the current vault under a compare-and-swap; a lost race is never retried.
#[tauri::command]
pub async fn sync_upload_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<SyncTransferResult, String> {
    let client = SyncClient::connect(&app)?;
    let identity = this_identity(&app)?;
    let current = client.download().await.map_err(present)?;
    let device_epoch = this_device_epoch(&client, &identity.device_id).await?;

    // Successor to the revision this device applied, not the service's current one.
    let state_file = crate::sync::state::state_path(&local_data_dir(&app)?);
    let base = crate::sync::state::read_protected(&state_file);
    let base_revision = base.as_ref().map(|entry| entry.revision).unwrap_or(0);

    let next_revision = match crate::sync::state::decide_upload(base_revision, current.revision) {
        crate::sync::state::UploadDecision::Offer { revision } => revision,
        crate::sync::state::UploadDecision::Conflict { server_revision } => {
            return Err(format!("sync_conflict:{server_revision}"));
        }
    };
    if let Some(base) = base.as_ref() {
        if base.vault_id != current.vault_id {
            return Err("This device is set up for a different synced vault.".into());
        }
    }

    // AEAD context binds the position this snapshot will occupy, so it precedes encryption.
    let aad = snapshot_aad(
        &current.vault_id,
        &identity.device_id,
        next_revision as u64,
        (next_revision as u64).saturating_sub(1),
        current.vault_epoch.max(1) as u64,
        device_epoch,
        crate::sync::envelope::OPERATION_SNAPSHOT,
    );
    let (blob, entry_count, plaintext_digest) = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session.as_ref().ok_or("Unlock Sesame before syncing.")?;
        let plaintext = serde_json::to_vec(&vault.payload)
            .map_err(|_| "Sesame could not prepare the vault for sync.".to_string())?;
        let digest = crate::sync::state::payload_digest(&plaintext);
        let blob = crate::vault::crypto::encrypt_bytes(&vault.key, &plaintext, &aad)?;
        (blob, vault.payload.entries.len(), digest)
    };

    let nonce = decode_bytes(&blob.nonce)?;
    let ciphertext = decode_bytes(&blob.ciphertext)?;
    let envelope = identity.seal_envelope(&crate::sync::envelope::EnvelopeDraft {
        vault_id: &current.vault_id,
        device_id: &identity.device_id,
        revision: next_revision as u64,
        vault_epoch: current.vault_epoch.max(1) as u64,
        device_epoch,
        operation: crate::sync::envelope::OPERATION_SNAPSHOT,
        tombstone_id: "",
        previous_digest: base
            .as_ref()
            .map(|entry| entry.head_digest.as_str())
            .unwrap_or(""),
        nonce: &nonce,
        ciphertext: &ciphertext,
    })?;
    let sent_digest = crate::sync::envelope::digest(&envelope);
    let body = serde_json::to_value(&envelope)
        .map_err(|_| "Sesame could not prepare the vault for sync.".to_string())?;
    let accepted = client.upload(&body).await.map_err(present)?;

    // Write the agreement only after the service accepted it, and verify the digest it recorded.
    if !accepted.digest.is_empty() && accepted.digest != sent_digest {
        return Err("Sesame Sync recorded a different version than this device sent.".into());
    }
    crate::sync::state::write_protected(
        &state_file,
        &crate::sync::state::SyncBase {
            version: 1,
            vault_id: current.vault_id.clone(),
            revision: accepted.revision,
            vault_epoch: accepted.vault_epoch,
            payload_digest: plaintext_digest,
            head_digest: sent_digest,
            receipt: accepted.receipt.clone(),
        },
    )?;
    Ok(SyncTransferResult {
        revision: accepted.revision,
        vault_epoch: accepted.vault_epoch,
        entry_count,
    })
}

/// Downloads, verifies the sender, and replaces the local vault; without a trusted base it refuses.
#[tauri::command]
pub async fn sync_download_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<SyncTransferResult, String> {
    let client = SyncClient::connect(&app)?;
    let (current, envelope, _) = fetch_verified_snapshot(&client).await?;

    let state_file = crate::sync::state::state_path(&local_data_dir(&app)?);
    let base = match crate::sync::state::read_protected(&state_file) {
        Some(base) => base,
        None => {
            return Err(
                "This device has no record of what it last synced. Join the synced vault from Sesame Sync settings before downloading."
                    .into(),
            )
        }
    };
    if base.vault_id != current.vault_id {
        return Err("This device is set up for a different synced vault.".into());
    }
    if current.revision < base.revision {
        return Err(format!(
            "The service offered revision {} after this device already applied {}.",
            current.revision, base.revision
        ));
    }

    let blob = crate::vault::types::CipherBlob {
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    let (entry_count, applied_digest) = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session.as_mut().ok_or("Unlock Sesame before syncing.")?;

        // An ordinary pull replaces the vault, so it must not run over edits never uploaded.
        let local = serde_json::to_vec(&vault.payload)
            .map_err(|_| "Sesame could not read the local vault.".to_string())?;
        if base.has_local_changes(&local) {
            return Err(
                "This device has changes that are not synced yet. Upload them, or resolve the difference."
                    .into(),
            );
        }

        let plaintext =
            crate::vault::crypto::decrypt_bytes(&vault.key, &blob, &snapshot_aad_for(&envelope))?;
        let payload: crate::vault::types::VaultPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| "The synced vault could not be read.".to_string())?;
        let count = payload.entries.len();
        let digest = crate::sync::state::payload_digest(&plaintext);
        crate::vault::storage::commit_payload_change(vault, payload)?;
        // Session epoch bumps before the lock releases: approvals must not release stale credentials.
        state.advance_session_epoch();
        (count, digest)
    };
    crate::browser_fill::cancel_pending_approvals(&app);

    crate::sync::state::write_protected(
        &state_file,
        &crate::sync::state::SyncBase {
            version: 1,
            vault_id: current.vault_id.clone(),
            revision: current.revision,
            vault_epoch: current.vault_epoch,
            payload_digest: applied_digest,
            head_digest: crate::sync::envelope::digest(&envelope),
            receipt: current.receipt.clone(),
        },
    )?;
    Ok(SyncTransferResult {
        revision: current.revision,
        vault_epoch: current.vault_epoch,
        entry_count,
    })
}

/// Downloads and verifies the snapshot: sender approval, signature, and response agreement.
async fn fetch_verified_snapshot(
    client: &SyncClient,
) -> Result<
    (
        crate::sync::client::DownloadedEnvelope,
        crate::sync::envelope::Envelope,
        String,
    ),
    String,
> {
    let current = client.download().await.map_err(present)?;
    let raw = current
        .envelope
        .clone()
        .ok_or("This vault has not been synced from another device yet.")?;
    let envelope: crate::sync::envelope::Envelope = serde_json::from_value(raw)
        .map_err(|_| "The synced vault could not be read.".to_string())?;

    let listing = client.devices().await.map_err(present)?;
    let sender = listing
        .devices
        .iter()
        .find(|device| device.device_id == envelope.device_id)
        .ok_or_else(|| "The device that uploaded this vault is not registered.".to_string())?;
    if sender.state != "approved" {
        return Err("The device that uploaded this vault is not approved.".into());
    }
    let verifying =
        ed25519_dalek::VerifyingKey::from_bytes(&decode_key(&sender.signing_public_key)?)
            .map_err(|_| "The synced vault could not be verified.".to_string())?;
    crate::sync::envelope::verify(&envelope, &verifying)?;

    if envelope.vault_id != current.vault_id
        || envelope.revision as i64 != current.revision
        || envelope.vault_epoch as i64 != current.vault_epoch
    {
        return Err("The synced vault does not match what the service described.".into());
    }
    let label = if sender.label.trim().is_empty() {
        "Another device".to_string()
    } else {
        sender.label.clone()
    };
    Ok((current, envelope, label))
}

async fn this_device_epoch(client: &SyncClient, device_id: &str) -> Result<u64, String> {
    let listing = client.devices().await.map_err(present)?;
    let device = listing
        .devices
        .iter()
        .find(|entry| entry.device_id == device_id)
        .ok_or_else(|| "This device is not registered for Sync.".to_string())?;
    if device.state != "approved" {
        return Err("This device is not approved to sync.".into());
    }
    Ok(device.device_epoch.max(1) as u64)
}

fn decode_key(value: &str) -> Result<[u8; 32], String> {
    decode_bytes(value)?
        .try_into()
        .map_err(|_| "A Sync device key is invalid.".to_string())
}

fn decode_bytes(value: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "A Sync value is not valid base64.".to_string())
}

include!("sync_transfer_recovery.rs");

/// Removes a device and rotates the vault key; every key operation happens in Rust.
#[tauri::command]
pub async fn sync_remove_device(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    device_id: String,
    master_password: String,
) -> Result<SyncRemovalResult, String> {
    let client = SyncClient::connect(&app)?;
    let identity = this_identity(&app)?;
    if device_id == identity.device_id {
        return Err("Turn Sesame Sync off on this device instead of removing it.".into());
    }
    let current = client.download().await.map_err(present)?;
    let listing = client.devices().await.map_err(present)?;

    let survivors: Vec<_> = listing
        .devices
        .iter()
        .filter(|device| {
            device.state == "approved"
                && device.device_id != device_id
                && device.device_id != identity.device_id
        })
        .collect();

    let device_epoch = this_device_epoch(&client, &identity.device_id).await?;
    let new_epoch = current.vault_epoch.max(1) as u64 + 1;

    // Old key never sent anywhere; it is dropped with the session.
    let mut new_key = [0_u8; 32];
    crate::vault::util::fill_random(&mut new_key);

    let (blob, entry_count, plaintext_digest) = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session.as_ref().ok_or("Unlock Sesame before syncing.")?;
        if vault.payload.vault_id.as_deref() != Some(current.vault_id.as_str()) {
            return Err("The unlocked vault is not the Sync vault for this account.".into());
        }
        // Verify the current wrapper before asking the service to commit: a mistype must not orphan every path.
        let wrapping_key = zeroize::Zeroizing::new(crate::vault::crypto::derive_key(
            &master_password,
            &vault.kdf,
        )?);
        let mut confirmed = crate::vault::crypto::decrypt_bytes(
            &wrapping_key,
            &vault.key_wrap,
            crate::vault::WRAP_AAD,
        )
        .map_err(|_| "That master password is not correct.".to_string())?;
        let matches = confirmed.as_slice() == vault.key.as_slice();
        confirmed.zeroize();
        if !matches {
            return Err("That master password is not correct.".into());
        }
        let plaintext = serde_json::to_vec(&vault.payload)
            .map_err(|_| "Sesame could not prepare the vault for sync.".to_string())?;
        let blob = crate::vault::crypto::encrypt_bytes(
            &new_key,
            &plaintext,
            &snapshot_aad(
                &current.vault_id,
                &identity.device_id,
                (current.revision + 1) as u64,
                current.revision as u64,
                new_epoch,
                new_epoch,
                crate::sync::envelope::OPERATION_SNAPSHOT,
            ),
        )?;
        (
            blob,
            vault.payload.entries.len(),
            crate::sync::state::payload_digest(&plaintext),
        )
    };

    let nonce = decode_bytes(&blob.nonce)?;
    let ciphertext = decode_bytes(&blob.ciphertext)?;
    let envelope = identity.seal_envelope(&crate::sync::envelope::EnvelopeDraft {
        vault_id: &current.vault_id,
        device_id: &identity.device_id,
        revision: (current.revision + 1) as u64,
        vault_epoch: new_epoch,
        device_epoch: new_epoch,
        operation: crate::sync::envelope::OPERATION_SNAPSHOT,
        tombstone_id: "",
        previous_digest: &current.digest,
        nonce: &nonce,
        ciphertext: &ciphertext,
    })?;

    let mut wrapped = Vec::with_capacity(survivors.len());
    for survivor in &survivors {
        let recipient = decode_key(&survivor.encryption_public_key)?;
        let sealed = crate::sync::keys::seal_vault_key(&new_key, &recipient, &current.vault_id)?;
        let encoded = crate::sync::keys::encode_package(&sealed);
        let signature =
            identity.sign_key_package(&current.vault_id, &survivor.device_id, &encoded)?;
        wrapped.push(serde_json::json!({
            "deviceId": survivor.device_id,
            "ciphertext": encoded,
            "signature": signature,
        }));
    }

    // Signed by this device: an account token alone cannot authorise or replay a removal.
    let intent = identity.sign_revocation_intent(&current.vault_id, &device_id, device_epoch)?;

    let body = serde_json::json!({
        "envelope": envelope,
        "survivors": wrapped,
        "intent": intent,
    });
    let accepted = client
        .rekey_device(&device_id, &body)
        .await
        .map_err(present)?;

    // Rebuild every wrap only after the service accepted; the recovery kit changes with the key.
    let recovery_kit = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session.as_mut().ok_or("Unlock Sesame before syncing.")?;
        let payload = vault.payload.clone();
        let recovery_kit = super::sync_adopt::adopt(vault, new_key, payload, &master_password)?;
        state.advance_session_epoch();
        recovery_kit
    };
    state.cache_pin_unlock(false);
    crate::commands::lifecycle::discard_pin_throttle_state(&app, &state);
    crate::browser_fill::cancel_pending_approvals(&app);

    let state_file = crate::sync::state::state_path(&local_data_dir(&app)?);
    crate::sync::state::write_protected(
        &state_file,
        &crate::sync::state::SyncBase {
            version: 1,
            vault_id: current.vault_id.clone(),
            revision: accepted.revision,
            vault_epoch: accepted.vault_epoch,
            payload_digest: plaintext_digest,
            head_digest: crate::sync::envelope::digest(&envelope),
            receipt: accepted.receipt.clone(),
        },
    )?;

    Ok(SyncRemovalResult {
        revision: accepted.revision,
        vault_epoch: accepted.vault_epoch,
        entry_count,
        recovery_kit,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRemovalResult {
    pub revision: i64,
    pub vault_epoch: i64,
    pub entry_count: usize,
    pub recovery_kit: String,
}

/// Refuses a device still waiting for approval. It never received the vault key, so nothing rotates.
#[tauri::command]
pub async fn sync_deny_device(app: AppHandle, device_id: String) -> Result<(), String> {
    let client = SyncClient::connect(&app)?;
    client.deny_device(&device_id).await.map_err(present)
}

/// Proves this device can act on its key package before the service treats it as live.
#[tauri::command]
pub async fn sync_activate_device(app: AppHandle) -> Result<(), String> {
    let client = SyncClient::connect(&app)?;
    let identity = this_identity(&app)?;
    let package = client
        .key_package(&identity.device_id)
        .await
        .map_err(present)?;
    let epoch = this_device_epoch(&client, &identity.device_id).await?;
    let proof = identity.sign_activation(&package.vault_id, epoch, &package.ciphertext)?;
    client.activate(&proof).await.map_err(present)
}

/// Empties the service-side vault when no device can read it. The local vault is untouched.
#[tauri::command]
pub async fn sync_reset_vault(app: AppHandle) -> Result<(), String> {
    let client = SyncClient::connect(&app)?;
    client.reset_vault().await.map_err(present)?;
    crate::sync::state::forget_protected(&crate::sync::state::state_path(&local_data_dir(&app)?))
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

/// Reads both sides of a conflict in memory; the local vault is not touched.
#[tauri::command]
pub async fn sync_conflict_details(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<SyncConflictView, String> {
    let client = SyncClient::connect(&app)?;
    let (current, envelope, sender_label) = fetch_verified_snapshot(&client).await?;
    let state_file = crate::sync::state::state_path(&local_data_dir(&app)?);
    let base = crate::sync::state::read_protected(&state_file);

    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
    let vault = session.as_ref().ok_or("Unlock Sesame before syncing.")?;
    let remote = decrypt_snapshot(&vault.key, &envelope)?;
    let remote_payload: crate::vault::types::VaultPayload = serde_json::from_slice(&remote)
        .map_err(|_| "The synced vault could not be read.".to_string())?;

    Ok(SyncConflictView {
        this_device: SyncConflictSideView {
            device_label: "This device".to_string(),
            revision: base.as_ref().map(|entry| entry.revision).unwrap_or(0),
            changed_at: String::new(),
            entry_count: vault.payload.entries.len(),
        },
        other_device: SyncConflictSideView {
            device_label: sender_label,
            revision: current.revision,
            changed_at: current.uploaded_at.clone(),
            entry_count: remote_payload.entries.len(),
        },
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResolutionResult {
    pub revision: i64,
    pub vault_epoch: i64,
    pub entry_count: usize,
    /// File names only: paths are a filesystem detail the webview has no business holding.
    pub recovery_copies: Vec<String>,
}

/// The only path that may discard a vault; recovery copies are verified before any apply.
#[tauri::command]
pub async fn sync_resolve_conflict(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    keep: String,
) -> Result<SyncResolutionResult, String> {
    let keep_this = match keep.as_str() {
        "this" => true,
        "other" => false,
        _ => return Err("Choose which vault to keep.".into()),
    };

    let client = SyncClient::connect(&app)?;
    let identity = this_identity(&app)?;
    let (current, envelope, _) = fetch_verified_snapshot(&client).await?;
    let device_epoch = this_device_epoch(&client, &identity.device_id).await?;
    let data_dir = local_data_dir(&app)?;
    let state_file = crate::sync::state::state_path(&data_dir);
    let base = crate::sync::state::read_protected(&state_file);
    let base_revision = base.as_ref().map(|entry| entry.revision).unwrap_or(0);
    if let Some(base) = base.as_ref() {
        if base.vault_id != current.vault_id {
            return Err("This device is set up for a different synced vault.".into());
        }
    }

    // Vault lock for this block only; the network work above and below runs without it.
    let (local_plaintext, remote_plaintext, local_entries, remote_entries, recovery_copies) = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session.as_ref().ok_or("Unlock Sesame before syncing.")?;

        let local = serde_json::to_vec(&vault.payload)
            .map_err(|_| "Sesame could not read the local vault.".to_string())?;
        let remote = decrypt_snapshot(&vault.key, &envelope)?;
        let remote_payload: crate::vault::types::VaultPayload = serde_json::from_slice(&remote)
            .map_err(|_| "The synced vault could not be read.".to_string())?;
        let remote_entries = remote_payload.entries.len();
        let local_entries = vault.payload.entries.len();

        let directory = crate::sync::conflict_backup::backup_dir(&data_dir);
        let stamp = backup_stamp();
        let mut written = Vec::with_capacity(2);
        for (side, revision, payload) in [
            (
                crate::sync::conflict_backup::Side::ThisDevice,
                base_revision,
                &local,
            ),
            (
                crate::sync::conflict_backup::Side::OtherDevice,
                current.revision,
                &remote,
            ),
        ] {
            let path = crate::sync::conflict_backup::write_verified(
                &directory, vault, side, revision, payload, &stamp,
            )?;
            written.push(path);
        }
        crate::sync::conflict_backup::prune(&directory, &written);
        let written: Vec<String> = written
            .into_iter()
            .map(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        (local, remote, local_entries, remote_entries, written)
    };

    // An edit landing in the upload window would be lost; both branches re-verify the captured digest.
    let captured_digest = crate::sync::state::payload_digest(&local_plaintext);

    if keep_this {
        let blob = {
            let session = state
                .session
                .lock()
                .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
            let vault = session.as_ref().ok_or("Unlock Sesame before syncing.")?;
            confirm_unchanged(vault, &captured_digest)?;
            crate::vault::crypto::encrypt_bytes(
                &vault.key,
                &local_plaintext,
                &snapshot_aad_for_draft(&crate::sync::envelope::EnvelopeDraft {
                    vault_id: &current.vault_id,
                    device_id: &identity.device_id,
                    revision: (current.revision + 1) as u64,
                    vault_epoch: current.vault_epoch.max(1) as u64,
                    device_epoch,
                    operation: crate::sync::envelope::OPERATION_SNAPSHOT,
                    tombstone_id: "",
                    previous_digest: &current.digest,
                    nonce: &[],
                    ciphertext: &[],
                }),
            )?
        };
        let nonce = decode_bytes(&blob.nonce)?;
        let ciphertext = decode_bytes(&blob.ciphertext)?;
        let sealed = identity.seal_envelope(&crate::sync::envelope::EnvelopeDraft {
            vault_id: &current.vault_id,
            device_id: &identity.device_id,
            revision: (current.revision + 1) as u64,
            vault_epoch: current.vault_epoch.max(1) as u64,
            device_epoch,
            operation: crate::sync::envelope::OPERATION_SNAPSHOT,
            tombstone_id: "",
            previous_digest: &current.digest,
            nonce: &nonce,
            ciphertext: &ciphertext,
        })?;
        let sent_digest = crate::sync::envelope::digest(&sealed);
        let body = serde_json::to_value(&sealed)
            .map_err(|_| "Sesame could not prepare the vault for sync.".to_string())?;
        let accepted = client.upload(&body).await.map_err(present)?;
        crate::sync::state::write_protected(
            &state_file,
            &crate::sync::state::SyncBase::new(
                &current.vault_id,
                accepted.revision,
                accepted.vault_epoch,
                &local_plaintext,
            )
            .with_head(&sent_digest, &accepted.receipt),
        )?;
        return Ok(SyncResolutionResult {
            revision: accepted.revision,
            vault_epoch: accepted.vault_epoch,
            entry_count: local_entries,
            recovery_copies,
        });
    }

    let payload: crate::vault::types::VaultPayload = serde_json::from_slice(&remote_plaintext)
        .map_err(|_| "The synced vault could not be read.".to_string())?;
    {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session.as_mut().ok_or("Unlock Sesame before syncing.")?;
        confirm_unchanged(vault, &captured_digest)?;
        crate::vault::storage::commit_payload_change(vault, payload)?;
        state.advance_session_epoch();
    }
    crate::browser_fill::cancel_pending_approvals(&app);
    crate::sync::state::write_protected(
        &state_file,
        &crate::sync::state::SyncBase::new(
            &current.vault_id,
            current.revision,
            current.vault_epoch,
            &remote_plaintext,
        )
        .with_head(&crate::sync::envelope::digest(&envelope), &current.receipt),
    )?;
    Ok(SyncResolutionResult {
        revision: current.revision,
        vault_epoch: current.vault_epoch,
        entry_count: remote_entries,
        recovery_copies,
    })
}

/// Refuses to continue if the local vault changed since capture: the recovery copy lacks later edits.
fn confirm_unchanged(vault: &crate::vault::UnlockedVault, captured: &str) -> Result<(), String> {
    let now = serde_json::to_vec(&vault.payload)
        .map_err(|_| "Sesame could not read the local vault.".to_string())?;
    if crate::sync::state::payload_digest(&now) != captured {
        return Err(
            "This vault changed while you were deciding. Open Sesame Sync and resolve the difference again."
                .into(),
        );
    }
    Ok(())
}

fn decrypt_snapshot(
    key: &[u8; 32],
    envelope: &crate::sync::envelope::Envelope,
) -> VaultResult<Vec<u8>> {
    let blob = crate::vault::types::CipherBlob {
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    crate::vault::crypto::decrypt_bytes(key, &blob, &snapshot_aad_for(envelope))
}

fn backup_stamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    format!("{seconds}")
}

/// Coordinator state for the Sync panel; paths, sites, and entries never cross IPC.
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
        Phase::Halted(Halt::Revoked) => ("halted", "revoked", 0),
        Phase::Halted(Halt::NotEntitled) => ("halted", "not_entitled", 0),
        Phase::Halted(Halt::Incompatible) => ("halted", "incompatible", 0),
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
) -> Result<SyncCoordinatorView, String> {
    use crate::sync::coordinator::{Halt, Outcome};

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

    let client = SyncClient::connect(app)?;
    let current = client.download().await.map_err(present)?;
    let state_file = crate::sync::state::state_path(&local_data_dir(app)?);
    let base = crate::sync::state::read_protected(&state_file);

    let has_local_changes = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session.as_ref().ok_or("sync_locked")?;
        let plaintext = serde_json::to_vec(&vault.payload)
            .map_err(|_| "Sesame could not read the local vault.".to_string())?;
        base.as_ref()
            .map(|entry| entry.has_local_changes(&plaintext))
            .unwrap_or(false)
    };

    match base.as_ref() {
        // Never synced: joining is deliberate, with a master password, not background work.
        None => Ok(Outcome::AlreadyCurrent),
        Some(entry) if has_local_changes => {
            let result = sync_upload_vault(app.clone(), state.clone()).await?;
            Ok(Outcome::Uploaded {
                revision: result.revision,
            })
        }
        Some(entry) if current.revision > entry.revision => {
            let result = sync_download_vault(app.clone(), state.clone()).await?;
            Ok(Outcome::Downloaded {
                revision: result.revision,
            })
        }
        Some(_) => Ok(Outcome::AlreadyCurrent),
    }
}

include!("sync_transfer_coordinator.rs");
