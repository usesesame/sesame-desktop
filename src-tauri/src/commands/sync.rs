//! Sync commands; compiled only under the `sync-preview` feature.
//! No key material crosses this boundary: the webview never receives or supplies a key.

use serde::Serialize;
use tauri::AppHandle;

use crate::sync::client::{SyncClient, SyncError};
use crate::vault::{VaultResult, VaultState};

/// The webview never sees the device's public keys; the approval ceremony stays in Rust.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncDeviceView {
    pub device_id: String,
    pub state: String,
    pub label: String,
    pub created_at: String,
    pub approved_at: Option<String>,
    pub revoked_at: Option<String>,
    pub is_this_device: bool,
    /// Binds the vault and both public keys, so a cross-device comparison authenticates.
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusView {
    pub enrolled: bool,
    pub state: String,
    pub vault_epoch: i64,
    pub devices: Vec<SyncDeviceView>,
}

/// Binds vault id, device id, and both public keys; domain-separated and public-key-only.
pub(super) fn approval_fingerprint(
    vault_id: &str,
    device_id: &str,
    signing_public_key: &str,
    encryption_public_key: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    for part in [
        b"sesame-sync-device-fingerprint-v1".as_slice(),
        vault_id.as_bytes(),
        device_id.as_bytes(),
        signing_public_key.as_bytes(),
        encryption_public_key.as_bytes(),
    ] {
        // Length-prefixed so field splits cannot collide: a concatenated digest is forgeable.
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    let bytes = digest.finalize();

    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut out = String::with_capacity(19);
    for (index, byte) in bytes.iter().take(10).enumerate() {
        if index > 0 && index % 2 == 0 {
            out.push(' ');
        }
        out.push(ALPHABET[(byte >> 3) as usize % ALPHABET.len()] as char);
        out.push(ALPHABET[(byte & 0x1f) as usize % ALPHABET.len()] as char);
    }
    out
}

pub(super) fn present(error: SyncError) -> String {
    match error {
        SyncError::Conflict {
            current_revision, ..
        } => format!("sync_conflict:{current_revision}"),
        other => other.to_string(),
    }
}

#[tauri::command]
pub async fn sync_status(app: AppHandle) -> Result<SyncStatusView, String> {
    let client = SyncClient::connect(&app)?;
    let this_device = crate::sync::identity::identity_path(&local_data_dir(&app)?);
    let this_device_id = crate::sync::identity::DeviceIdentity::load(&this_device)
        .ok()
        .map(|identity| identity.device_id.clone());

    let listing = client.devices().await.map_err(present)?;
    let devices = listing
        .devices
        .into_iter()
        .map(|device| SyncDeviceView {
            is_this_device: Some(&device.device_id) == this_device_id.as_ref(),
            fingerprint: approval_fingerprint(
                &listing.vault_id,
                &device.device_id,
                &device.signing_public_key,
                &device.encryption_public_key,
            ),
            device_id: device.device_id,
            state: device.state,
            label: device.label,
            created_at: device.created_at,
            approved_at: device.approved_at,
            revoked_at: device.revoked_at,
        })
        .collect::<Vec<_>>();
    let state = devices
        .iter()
        .find(|device| device.is_this_device)
        .map(|device| device.state.clone())
        .unwrap_or_else(|| "not_enrolled".to_string());
    Ok(SyncStatusView {
        enrolled: this_device_id.is_some(),
        state,
        vault_epoch: listing.vault_epoch,
        devices,
    })
}

/// The signing key never leaves this call graph; a pending device can decrypt nothing.
#[tauri::command]
pub async fn sync_enroll_device(app: AppHandle, label: String) -> Result<SyncDeviceView, String> {
    let label = label.trim().to_string();
    if label.is_empty() || label.chars().count() > 64 {
        return Err("Give this device a name of 1 to 64 characters.".into());
    }
    let client = SyncClient::connect(&app)?;
    let directory = local_data_dir(&app)?;
    let path = crate::sync::identity::identity_path(&directory);

    let identity = match crate::sync::identity::DeviceIdentity::load(&path) {
        Ok(existing) => existing,
        Err(_) => {
            let generated = crate::sync::identity::DeviceIdentity::generate()?;
            generated.save(&path)?;
            generated
        }
    };

    let proposed_vault_id = crate::sync::identity::random_opaque_id()?;
    let challenge = client
        .enroll_begin(&proposed_vault_id)
        .await
        .map_err(present)?;
    // Sign the service's vault id, never the proposed one.
    let proof = identity.enrollment_proof(&challenge.vault_id, &challenge.challenge)?;
    let device = client
        .enroll_finish(
            &identity.device_id,
            &encode_key(identity.signing_public_key()),
            &encode_key(identity.encryption_public_key()),
            &challenge.challenge,
            &proof,
            &label,
        )
        .await
        .map_err(present)?;
    // Fingerprint from locally held keys only: the service must not supply the compared values.
    if device.device_id != identity.device_id {
        return Err("Sesame Sync returned a different device. Set this device up again.".into());
    }
    Ok(SyncDeviceView {
        is_this_device: true,
        fingerprint: approval_fingerprint(
            &challenge.vault_id,
            &identity.device_id,
            &encode_key(identity.signing_public_key()),
            &encode_key(identity.encryption_public_key()),
        ),
        device_id: device.device_id,
        state: device.state,
        label: device.label,
        created_at: device.created_at,
        approved_at: device.approved_at,
        revoked_at: device.revoked_at,
    })
}

fn this_device_identity(app: &AppHandle) -> Result<crate::sync::identity::DeviceIdentity, String> {
    let path = crate::sync::identity::identity_path(&local_data_dir(app)?);
    crate::sync::identity::DeviceIdentity::load(&path)
        .map_err(|_| "Set up Sesame Sync on this device first.".to_string())
}

/// This device's fingerprint from its own keys, so the joining screen can show it.
#[tauri::command]
pub async fn sync_this_device_fingerprint(app: AppHandle) -> Result<String, String> {
    let client = SyncClient::connect(&app)?;
    let identity = this_device_identity(&app)?;
    // The vault id is not key material; a lying service produces a mismatch, which is the point.
    let current = client.download().await.map_err(present)?;
    Ok(approval_fingerprint(
        &current.vault_id,
        &identity.device_id,
        &encode_key(identity.signing_public_key()),
        &encode_key(identity.encryption_public_key()),
    ))
}

/// A pending device frozen at the moment its fingerprint was shown; nothing is fetched again.
struct FrozenDevice {
    device_id: String,
    signing_public_key: String,
    encryption_public_key: String,
    vault_id: String,
    vault_epoch: i64,
    session_epoch: u64,
    prepared_at: std::time::Instant,
}

/// Long enough to compare aloud, short enough to expire overnight.
const APPROVAL_VALIDITY: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Webview gets only a handle; it cannot name a device to seal to.
static PREPARED: std::sync::Mutex<Option<std::collections::HashMap<String, FrozenDevice>>> =
    std::sync::Mutex::new(None);

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedApproval {
    pub handle: String,
    pub device_id: String,
    pub label: String,
    /// Computed over the frozen keys; the value the person compares.
    pub fingerprint: String,
}

/// Freezes a pending device; nothing is sealed and no vault material is touched.
#[tauri::command]
pub async fn sync_prepare_approval(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    device_id: String,
) -> Result<PreparedApproval, String> {
    let client = SyncClient::connect(&app)?;
    let current = client.download().await.map_err(present)?;
    let listing = client.devices().await.map_err(present)?;
    let device = listing
        .devices
        .into_iter()
        .find(|entry| entry.device_id == device_id)
        .ok_or_else(|| "That device is not registered.".to_string())?;
    if device.state != "pending" {
        return Err("That device is not waiting for approval.".into());
    }
    decode_public_key(&device.encryption_public_key)?;
    decode_public_key(&device.signing_public_key)?;

    let fingerprint = approval_fingerprint(
        &current.vault_id,
        &device.device_id,
        &device.signing_public_key,
        &device.encryption_public_key,
    );
    let handle = crate::sync::identity::random_opaque_id()?;
    let frozen = FrozenDevice {
        device_id: device.device_id.clone(),
        signing_public_key: device.signing_public_key,
        encryption_public_key: device.encryption_public_key,
        vault_id: current.vault_id,
        vault_epoch: current.vault_epoch,
        session_epoch: state.session_epoch(),
        prepared_at: std::time::Instant::now(),
    };
    {
        let mut prepared = PREPARED
            .lock()
            .map_err(|_| "Sesame could not prepare that approval.".to_string())?;
        let map = prepared.get_or_insert_with(std::collections::HashMap::new);
        map.retain(|_, entry| entry.prepared_at.elapsed() < APPROVAL_VALIDITY);
        map.insert(handle.clone(), frozen);
    }
    Ok(PreparedApproval {
        handle,
        device_id: device.device_id,
        label: device.label,
        fingerprint,
    })
}

/// Consumes the handle either way, so a confirmation cannot be replayed.
#[tauri::command]
pub async fn sync_approve_prepared_device(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    handle: String,
) -> Result<SyncDeviceView, String> {
    let frozen = {
        let mut prepared = PREPARED
            .lock()
            .map_err(|_| "Sesame could not complete that approval.".to_string())?;
        prepared
            .as_mut()
            .and_then(|map| map.remove(&handle))
            .ok_or_else(|| {
                "That approval is no longer valid. Compare the codes again.".to_string()
            })?
    };
    if frozen.prepared_at.elapsed() >= APPROVAL_VALIDITY {
        return Err("That approval expired. Compare the codes again.".into());
    }
    if state.session_epoch() != frozen.session_epoch {
        return Err("That approval is no longer current. Compare the codes again.".into());
    }
    super::sync_transfer::approve_frozen_device(
        app,
        state,
        &frozen.vault_id,
        frozen.vault_epoch,
        frozen.session_epoch,
        &frozen.device_id,
        &frozen.signing_public_key,
        &frozen.encryption_public_key,
    )
    .await
}

/// Revokes the device, then deletes the local identity; the local vault is untouched.
#[tauri::command]
pub async fn sync_disable(app: AppHandle, force: Option<bool>) -> Result<(), String> {
    let path = crate::sync::identity::identity_path(&local_data_dir(&app)?);
    let identity = crate::sync::identity::DeviceIdentity::load(&path).ok();

    // Local keys go only after the service confirms the revocation, unless the caller forces it.
    if let Some(identity) = identity {
        let revoked = match SyncClient::connect(&app) {
            Ok(client) => client.revoke_device(&identity.device_id).await.is_ok(),
            Err(_) => false,
        };
        if !revoked && !force.unwrap_or(false) {
            return Err(
                "Sesame could not tell the service to remove this device, so its keys were kept. Try again, or remove it from another device."
                    .into(),
            );
        }
    }
    crate::sync::identity::forget(&path)?;
    crate::sync::state::forget_protected(&crate::sync::state::state_path(&local_data_dir(&app)?))
}

pub(super) fn local_data_dir(app: &AppHandle) -> VaultResult<std::path::PathBuf> {
    use tauri::Manager;
    app.path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())
}

fn decode_public_key(value: &str) -> Result<[u8; 32], String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "That device offered a key Sesame cannot use.".to_string())?
        .try_into()
        .map_err(|_| "That device offered a key Sesame cannot use.".to_string())
}

fn encode_key(bytes: [u8; 32]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}
