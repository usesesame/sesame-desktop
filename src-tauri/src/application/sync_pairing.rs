use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use zeroize::Zeroize;

use crate::application::sync::{
    present, present_proof, refresh, vault_id_of, verify_master_password, SyncStore,
};
use crate::sync::client::{PairingRecord, SyncClient, SyncError};
use crate::sync::engine::{add_entry, seal_label, NewDevice};
use crate::sync::identity::DeviceIdentity;
use crate::sync::pairing::{ApproverIdentity, NewDeviceIdentity};
use crate::sync::pake;
use crate::sync::request::KeyPackageV3;
use crate::vault::VaultState;

pub(crate) const PAIRING_WINDOW: Duration = Duration::from_secs(10 * 60);

struct ShownCode {
    code: String,
    shown_at: Instant,
}

static SHOWN: Mutex<Option<ShownCode>> = Mutex::new(None);
static CANCELLED: AtomicBool = AtomicBool::new(false);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingCodeView {
    pub code: String,
    pub expires_in_seconds: u64,
}

pub(crate) fn take_shown_code() -> Result<String, String> {
    let guard = SHOWN
        .lock()
        .map_err(|_| "Sesame could not read the pairing code.".to_string())?;
    let shown = guard
        .as_ref()
        .ok_or("Show a pairing code on this device first.")?;
    if shown.shown_at.elapsed() >= PAIRING_WINDOW {
        return Err("That pairing code expired. Show a new one.".into());
    }
    Ok(shown.code.clone())
}

pub(crate) fn clear_shown_code() {
    if let Ok(mut guard) = SHOWN.lock() {
        if let Some(mut shown) = guard.take() {
            shown.code.zeroize();
        }
    }
}

pub(crate) fn cancelled() -> Result<(), String> {
    if CANCELLED.load(Ordering::SeqCst) {
        return Err("Pairing was cancelled.".into());
    }
    Ok(())
}

pub(crate) fn reset_cancellation() {
    CANCELLED.store(false, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn set_cancelled() {
    CANCELLED.store(true, Ordering::SeqCst);
}

pub(crate) fn pairing_code() -> Result<PairingCodeView, String> {
    let code = crate::sync::pake::generate_code()?;
    reset_cancellation();
    let mut guard = SHOWN
        .lock()
        .map_err(|_| "Sesame could not prepare a pairing code.".to_string())?;
    *guard = Some(ShownCode {
        code: code.clone(),
        shown_at: Instant::now(),
    });
    Ok(PairingCodeView {
        code,
        expires_in_seconds: PAIRING_WINDOW.as_secs(),
    })
}

pub(crate) fn cancel_pairing() -> Result<(), String> {
    CANCELLED.store(true, Ordering::SeqCst);
    clear_shown_code();
    Ok(())
}

pub(crate) const CLASSICAL_KEY_REFUSAL: &str = "This device only supports the older key exchange, and this vault already uses the newer one. Update Sesame on the new device, or allow the older key exchange and try again.";

pub(crate) fn refuse_classical_downgrade<'a>(
    offered_package_key: &str,
    member_package_keys: impl Iterator<Item = &'a str>,
    allow_classical: bool,
) -> Result<(), String> {
    let length = |encoded: &str| {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_or(0, |bytes| bytes.len())
    };
    let offered_is_classical = length(offered_package_key) == crate::sync::keys::X25519_KEY_BYTES;
    let vault_has_hybrid = member_package_keys
        .into_iter()
        .any(|key| length(key) == crate::sync::xwing::PUBLIC_KEY_BYTES);
    if offered_is_classical && vault_has_hybrid && !allow_classical {
        return Err(CLASSICAL_KEY_REFUSAL.to_string());
    }
    Ok(())
}

pub(crate) fn newcomer_matches_offer(
    newcomer: &NewDeviceIdentity,
    offered: &PairingRecord,
) -> bool {
    newcomer.device_id == offered.device_id
        && newcomer.signing_key == offered.signing_key
        && newcomer.package_key
            == crate::sync::pairing::package_key_commitment(&offered.package_key)
}

pub(crate) fn clean_join_label(label: &str) -> Result<String, String> {
    let label = label.trim().to_string();
    if label.is_empty() || label.len() > crate::sync::pairing::MAX_FIELD_BYTES {
        return Err("Give this device a short name.".into());
    }
    Ok(label)
}

pub(crate) fn verify_master_password_now_in_state(
    state: &VaultState,
    master_password: &str,
) -> Result<(), String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
    let unlocked = session
        .as_ref()
        .ok_or("Unlock Sesame before joining a synced vault.")?;
    verify_master_password(unlocked, master_password)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedDeviceView {
    pub label: String,
}

pub(crate) struct ApproveRequest<'a> {
    pub code: &'a str,
    pub started: Instant,
    pub allow_classical: bool,
}

pub(crate) async fn approve_in_state<P, F>(
    vault: &VaultState,
    store: &SyncStore,
    client: &SyncClient,
    identity: &DeviceIdentity,
    request: ApproveRequest<'_>,
    pause: P,
) -> Result<ApprovedDeviceView, String>
where
    P: Fn() -> F,
    F: Future<Output = ()>,
{
    let ApproveRequest {
        code,
        started,
        allow_classical,
    } = request;
    store.require_no_pending_key_change()?;
    let local = store
        .load_state()?
        .ok_or("Set up Sesame Sync on this device first.")?;

    let refreshed = refresh(client, &local).await?;
    if refreshed.server.device_state != "approved"
        || refreshed.server.activated_epoch != refreshed.server.vault_epoch
    {
        return Err(
            "This device must take the current vault key before it can add another device.".into(),
        );
    }
    let mut state = local.clone();
    state.entries = refreshed.update.entries.clone();
    store.save_state(&state)?;
    let list = refreshed.update.list;
    if refreshed.server.current_revision == 0 {
        return Err("Sync this vault once before adding a device.".into());
    }

    let offered = loop {
        cancelled()?;
        if started.elapsed() >= PAIRING_WINDOW {
            return Err("No device entered the code in time.".into());
        }
        let view = client.devices().await.map_err(present)?;
        if let Some(found) = view
            .pairings
            .into_iter()
            .find(|pairing| pairing.state == "offered")
        {
            break found;
        }
        pause().await;
    };
    if let Err(refusal) = refuse_classical_downgrade(
        &offered.package_key,
        list.current()
            .iter()
            .map(|member| member.package_key.as_str()),
        allow_classical,
    ) {
        let _ = client.cancel_pairing(identity, &offered.device_id).await;
        return Err(refusal);
    }
    let offer = URL_SAFE_NO_PAD
        .decode(&offered.offer)
        .map_err(|_| "The pairing message could not be read.".to_string())?;

    let ad = ApproverIdentity {
        device_id: identity.device_id.clone(),
        signing_key: URL_SAFE_NO_PAD.encode(identity.signing_public_key()),
        vault_id: state.vault_id.clone(),
        head_digest: list.head_digest().to_string(),
    }
    .encode()
    .ok_or("Sesame could not prepare the pairing message.")?;
    let (answered, new_ad) = pake::answer(code, &offer, &ad)?;
    let newcomer =
        NewDeviceIdentity::decode(&new_ad).ok_or("The pairing message could not be read.")?;
    if !newcomer_matches_offer(&newcomer, &offered) {
        let _ = client.cancel_pairing(identity, &offered.device_id).await;
        return Err(
            "The device and the service disagree about the new device's keys. Pairing stopped."
                .into(),
        );
    }
    client
        .answer_pairing(identity, &offered.device_id, &answered.message)
        .await
        .map_err(present)?;

    let confirmation = loop {
        cancelled()?;
        if started.elapsed() >= PAIRING_WINDOW {
            return Err("The new device did not finish in time.".into());
        }
        let view = client.devices().await.map_err(present)?;
        if let Some(found) = view
            .pairings
            .into_iter()
            .find(|pairing| pairing.device_id == offered.device_id)
        {
            if let Some(message) = found.confirm {
                break message;
            }
        } else {
            return Err("The new device left before finishing.".into());
        }
        pause().await;
    };
    let confirmation = URL_SAFE_NO_PAD
        .decode(confirmation)
        .map_err(|_| "The pairing message could not be read.".to_string())?;
    if answered.verify_confirmation(&confirmation).is_err() {
        let _ = client.cancel_pairing(identity, &offered.device_id).await;
        return Err(
            "The code on the new device did not match. Show a new code and try again.".into(),
        );
    }

    let recipient = URL_SAFE_NO_PAD
        .decode(&offered.package_key)
        .map_err(|_| "The new device offered a key Sesame cannot use.".to_string())?;
    let (sealed_label, package_bytes) = {
        let session = vault
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session
            .as_ref()
            .ok_or("Unlock Sesame before adding a device.")?;
        if vault_id_of(unlocked)? != state.vault_id {
            return Err("The unlocked vault is not the Sync vault.".into());
        }
        unlocked.expose_vault_key(|key| {
            let label = seal_label(key, &state.vault_id, &newcomer.device_id, &newcomer.label)
                .map_err(present_proof)?;
            let package = crate::sync::keys::seal_for_recipient(
                key,
                &recipient,
                &state.vault_id,
                list.epoch(),
            )?;
            Ok((label, package))
        })?
    };
    let entry = add_entry(
        identity,
        &list,
        &NewDevice {
            device_id: &newcomer.device_id,
            signing_key: &newcomer.signing_key,
            package_key: &offered.package_key,
        },
        &sealed_label,
        refreshed.server.current_revision,
    )
    .map_err(present_proof)?;
    let package = identity.sign_key_package(KeyPackageV3 {
        vault_id: state.vault_id.clone(),
        sender_device_id: identity.device_id.clone(),
        recipient_device_id: newcomer.device_id.clone(),
        vault_epoch: list.epoch(),
        entry_digest: entry.digest(),
        ciphertext: URL_SAFE_NO_PAD.encode(&package_bytes),
        signature: String::new(),
    });
    client
        .approve(identity, &entry, &package)
        .await
        .map_err(|error| match error {
            SyncError::Conflict => {
                "Another device changed the device list. Show a new code and try again.".to_string()
            }
            other => present(other),
        })?;
    let mut next = state;
    next.entries.push(entry);
    store.save_state(&next)?;
    Ok(ApprovedDeviceView {
        label: newcomer.label,
    })
}
