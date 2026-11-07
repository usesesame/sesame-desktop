use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use zeroize::Zeroize;

use crate::application::sync::verify_master_password;
use crate::sync::client::PairingRecord;
use crate::sync::pairing::NewDeviceIdentity;
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
