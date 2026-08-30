//! Joining a vault another device is already syncing; compiled only under `sync-preview`.
//! Re-keying requires the master password again: proving you own the vault is the point.

use serde::Serialize;
use tauri::AppHandle;
use zeroize::Zeroize;

use super::sync::{local_data_dir, present};
use crate::sync::client::SyncClient;
use crate::sync::envelope::snapshot_aad_for;
use crate::vault::crypto::{
    bytes_match, decrypt_bytes, default_kdf_params, derive_key, encrypt_bytes,
};
use crate::vault::util::generate_recovery_kit;
use crate::vault::{VaultState, RECOVERY_WRAP_AAD, WRAP_AAD};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncAdoptResult {
    pub entry_count: usize,
    pub revision: i64,
    /// Shown once; the old kit stopped working with the key change.
    pub recovery_kit: String,
}

/// Order matters: everything fallible happens before the local vault is touched.
#[tauri::command]
pub async fn sync_adopt_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    master_password: String,
) -> Result<SyncAdoptResult, String> {
    let client = SyncClient::connect(&app)?;
    let path = crate::sync::identity::identity_path(&local_data_dir(&app)?);
    let identity = crate::sync::identity::DeviceIdentity::load(&path)
        .map_err(|_| "Set up Sesame Sync on this device first.".to_string())?;

    // No package means approval has not happened yet.
    let package = client
        .key_package(&identity.device_id)
        .await
        .map_err(present)?;
    let current = client.download().await.map_err(present)?;
    let raw = current
        .envelope
        .ok_or("The other device has not uploaded this vault yet.")?;
    let envelope: crate::sync::envelope::Envelope = serde_json::from_value(raw)
        .map_err(|_| "The synced vault could not be read.".to_string())?;

    // Both must come from approved devices: a revoked one cannot hand over a key or vault.
    let listing = client.devices().await.map_err(present)?;
    let sender = listing
        .devices
        .iter()
        .find(|device| device.device_id == envelope.device_id)
        .ok_or_else(|| "The device that uploaded this vault is not registered.".to_string())?;
    if sender.state != "approved" {
        return Err("The device that uploaded this vault is not approved.".into());
    }
    let signer = listing
        .devices
        .iter()
        .find(|device| device.device_id == package.sender_device_id)
        .ok_or_else(|| "The device that approved this one is not registered.".to_string())?;
    if signer.state != "approved" {
        return Err("The device that approved this one is no longer approved.".into());
    }
    if package.recipient_device_id != identity.device_id {
        return Err("That key package is addressed to a different device.".into());
    }

    let sealed = crate::sync::keys::decode_package(&package.ciphertext)?;
    verify_package_signature(
        &signer.signing_public_key,
        &current.vault_id,
        &package.sender_device_id,
        &package.recipient_device_id,
        &package.ciphertext,
        &package.signature,
    )?;

    let mut vault_key = identity.open_key_package(&sealed, &current.vault_id)?;
    let key: [u8; 32] = vault_key
        .as_slice()
        .try_into()
        .map_err(|_| "The synced vault key is invalid.".to_string())?;
    vault_key.zeroize();

    let verifying =
        ed25519_dalek::VerifyingKey::from_bytes(&decode_key(&sender.signing_public_key)?)
            .map_err(|_| "The synced vault could not be verified.".to_string())?;
    crate::sync::envelope::verify(&envelope, &verifying)?;

    let blob = crate::vault::types::CipherBlob {
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    let mut plaintext = decrypt_bytes(&key, &blob, &snapshot_aad_for(&envelope))?;
    let payload: crate::vault::types::VaultPayload = serde_json::from_slice(&plaintext)
        .map_err(|_| "The synced vault could not be read.".to_string())?;
    plaintext.zeroize();
    let entry_count = payload.entries.len();

    let recovery_kit = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session
            .as_mut()
            .ok_or("Unlock Sesame before joining a synced vault.")?;

        // Proves ownership of this vault before its key is replaced.
        let wrapping_key = derive_key(&master_password, &vault.kdf)?;
        let mut confirmed = decrypt_bytes(&wrapping_key, &vault.key_wrap, WRAP_AAD)
            .map_err(|_| "That master password is not correct.".to_string())?;
        let matches = vault.expose_vault_key(|key| Ok(bytes_match(confirmed.as_slice(), key)))?;
        confirmed.zeroize();
        if !matches {
            return Err("That master password is not correct.".into());
        }

        let recovery_kit = adopt(vault, key, payload, &master_password)?;
        // Epoch advances before lock release so a waiting approval cannot write into the adopted vault.
        state.advance_session_epoch();
        recovery_kit
    };
    state.cache_pin_unlock(false);
    crate::commands::lifecycle::discard_pin_throttle_state(&app, &state);
    crate::browser_fill::cancel_pending_approvals(&app);

    Ok(SyncAdoptResult {
        entry_count,
        revision: current.revision,
        recovery_kit,
    })
}

/// Old-key wraps are rebuilt or dropped; a stale PIN wrap would unlock a vault this one cannot read.
pub(super) fn adopt(
    vault: &mut crate::vault::UnlockedVault,
    mut key: [u8; 32],
    payload: crate::vault::types::VaultPayload,
    master_password: &str,
) -> Result<String, String> {
    let kdf = default_kdf_params();
    let wrapping_key = zeroize::Zeroizing::new(derive_key(master_password, &kdf)?);
    let key_wrap = encrypt_bytes(&wrapping_key, &key, WRAP_AAD)?;

    let mut recovery_kit = generate_recovery_kit();
    let shown = recovery_kit.clone();
    let recovery_kdf = default_kdf_params();
    let recovery_wrapping_key = zeroize::Zeroizing::new(derive_key(&recovery_kit, &recovery_kdf)?);
    recovery_kit.zeroize();
    let recovery_wrap = encrypt_bytes(&recovery_wrapping_key, &key, RECOVERY_WRAP_AAD)?;

    let protected_key = crate::vault::VaultKey::new(key)?;
    key.zeroize();
    let previous = (
        std::mem::replace(&mut vault.kdf, kdf),
        std::mem::replace(&mut vault.key_wrap, key_wrap),
        std::mem::replace(&mut vault.recovery_kdf, Some(recovery_kdf)),
        std::mem::replace(&mut vault.recovery_wrap, Some(recovery_wrap)),
        std::mem::replace(&mut vault.pin_wrap, None),
        vault.replace_vault_key(protected_key),
    );

    if let Err(error) =
        crate::vault::storage::commit_payload_change_without_previous(vault, payload)
    {
        // Nothing partially applied: a failed write restores the old key and contents.
        vault.kdf = previous.0;
        vault.key_wrap = previous.1;
        vault.recovery_kdf = previous.2;
        vault.recovery_wrap = previous.3;
        vault.pin_wrap = previous.4;
        vault.replace_vault_key(previous.5);
        return Err(error);
    }
    Ok(shown)
}

/// One canonical payload lives in `sync::identity`; all three parties verify the same bytes.
fn verify_package_signature(
    signing_public_key: &str,
    vault_id: &str,
    sender_device_id: &str,
    recipient_device_id: &str,
    encoded_ciphertext: &str,
    signature: &str,
) -> Result<(), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::Verifier;

    let key = ed25519_dalek::VerifyingKey::from_bytes(&decode_key(signing_public_key)?)
        .map_err(|_| "That key package could not be verified.".to_string())?;
    let bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "That key package could not be verified.".to_string())?
        .try_into()
        .map_err(|_| "That key package could not be verified.".to_string())?;
    let payload = crate::sync::identity::key_package_signing_payload(
        vault_id,
        sender_device_id,
        recipient_device_id,
        encoded_ciphertext,
    )?;
    key.verify(&payload, &ed25519_dalek::Signature::from_bytes(&bytes))
        .map_err(|_| "That key package was not signed by the approving device.".to_string())
}

fn decode_key(value: &str) -> Result<[u8; 32], String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "A Sync device key is invalid.".to_string())?
        .try_into()
        .map_err(|_| "A Sync device key is invalid.".to_string())
}
