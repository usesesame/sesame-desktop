use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::{Zeroize, Zeroizing};

use crate::application::lifecycle::{
    begin_unlock, confirm_unlock_survived, install_unlocked_session, key_settings_in_state,
    unlock_with_derived_key,
};
use crate::application::DesktopEffects;
use crate::vault::crypto::decrypt_bytes;
use crate::vault::key_proof::{NewKeyWraps, NewPinWrap, NewRecoveryKit, SecretProof};
use crate::vault::storage::{
    commit_master_password_rotation, complete_recovery_setup_with, derive_pin_wrapping_key,
    prove_rotation_credentials, remove_hello_for_session, remove_pin_for_session,
    resume_recovery_setup_with, set_hello_for_session, set_pin_with, validate_new_unlock_pin,
    validate_unlock_pin, write_vault_file, RotationCredentials,
};
use crate::vault::throttle::PinAttemptGuard;
use crate::vault::util::{random_id, read_file_with_limit};
use crate::vault::windows_hello;
use crate::vault::{
    ChangeMasterPasswordRequest, ChangeMasterPasswordResult, HelloWrap, UnlockedVault, VaultResult,
    VaultSetup, VaultSnapshot, VaultState, VaultStatus, HELLO_KEY_NAME_PREFIX,
    MAX_VAULT_FILE_BYTES, PIN_WRAP_AAD,
};

pub fn establish_pin_throttle_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
) -> VaultResult<()> {
    let mut guard = state
        .pin_guard
        .lock()
        .map_err(|_| "Sesame could not read the PIN protection state.".to_string())?;
    guard.record_success();
    effects.write_pin_throttle_state(&guard)?;
    state.mark_pin_throttle_loaded();
    Ok(())
}

pub fn discard_pin_throttle_state(state: &VaultState, effects: &dyn DesktopEffects) {
    if let Ok(mut guard) = state.pin_guard.lock() {
        guard.record_success();
        state.mark_pin_throttle_loaded();
    }
    let _ = effects.clear_pin_throttle_state();
}

pub fn get_vault_status_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
) -> VaultResult<VaultStatus> {
    let path = effects.vault_path()?;
    let exists = path.exists();
    let pin_unlock_available = if !exists {
        state.cache_pin_unlock(false);
        false
    } else if let Some(cached) = state.cached_pin_unlock() {
        cached
    } else {
        let available = stored_vault_has_pin(&path);
        state.cache_pin_unlock(available);
        available
    };
    let hello_unlock_available = if !exists {
        state.cache_hello_unlock(false);
        false
    } else if let Some(cached) = state.cached_hello_unlock() {
        cached
    } else {
        let available = stored_vault_has_hello(&path);
        state.cache_hello_unlock(available);
        available
    };
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault state.".to_string())?;
    let unlocked = session.is_some();
    let (vault_id, revision, onboarding_required) = if let Some(session) = session.as_ref() {
        let snapshot = session.snapshot();
        (
            snapshot.vault_id,
            snapshot.revision,
            !session.setup_complete,
        )
    } else {
        Default::default()
    };
    drop(session);

    Ok(VaultStatus {
        exists,
        unlocked,
        preview: false,
        pin_unlock_available,
        hello_unlock_available,
        onboarding_required,
        vault_id,
        revision,
    })
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredVaultPinStatus {
    #[serde(default)]
    pin_wrap: Option<serde::de::IgnoredAny>,
}

fn stored_vault_has_pin(path: &std::path::Path) -> bool {
    let Ok(bytes) = read_file_with_limit(path, MAX_VAULT_FILE_BYTES) else {
        return false;
    };
    serde_json::from_slice::<StoredVaultPinStatus>(&bytes)
        .ok()
        .and_then(|status| status.pin_wrap)
        .is_some()
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredVaultHelloStatus {
    #[serde(default)]
    hello_wrap: Option<serde::de::IgnoredAny>,
}

fn stored_vault_has_hello(path: &std::path::Path) -> bool {
    let Ok(bytes) = read_file_with_limit(path, MAX_VAULT_FILE_BYTES) else {
        return false;
    };
    serde_json::from_slice::<StoredVaultHelloStatus>(&bytes)
        .ok()
        .and_then(|status| status.hello_wrap)
        .is_some()
}

pub fn create_vault_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
    master_password: Zeroizing<String>,
) -> VaultResult<VaultSetup> {
    let (opened, recovery_kit_for_display) =
        sesame_core::api::create_vault(&master_password, "My Sesame vault")?;
    drop(master_password);
    // Session guard first: a concurrent restore must not race the file creation.
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not open the vault session.".to_string())?;
    let path = effects.vault_path()?;
    if path.exists() {
        return Err("A local Sesame vault already exists on this device.".into());
    }
    write_vault_file(&path, &opened.file)?;
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    let _ = crate::application::unlock::establish_pin_throttle_state(state, effects);

    // `OpenedVault` zeroizes on drop, so clone and let it drop rather than moving fields out.
    let unlocked = UnlockedVault::from_opened(path, &opened)?;
    effects.report_key_page_fallback(&unlocked);
    let snapshot = unlocked.snapshot();
    *session = Some(unlocked);
    state.advance_session_epoch();
    Ok(VaultSetup {
        snapshot,
        recovery_kit: recovery_kit_for_display,
    })
}

/// Replacement kit for an interrupted setup; only the still-empty pending vault can use this path.
pub fn resume_recovery_setup_in_state(state: &VaultState) -> VaultResult<String> {
    const LOCKED: &str = "Unlock your vault before resuming recovery setup.";
    key_settings_in_state(state, LOCKED)?;
    let recovery = NewRecoveryKit::generate()?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_mut().ok_or(LOCKED)?;
    resume_recovery_setup_with(session, &recovery)
}

/// Host-owned recovery gate: a renderer preference cannot satisfy it.
pub fn complete_recovery_setup_in_state(
    state: &VaultState,
    recovery_kit: Zeroizing<String>,
) -> VaultResult<()> {
    const LOCKED: &str = "Unlock your vault before completing recovery setup.";
    let settings = key_settings_in_state(state, LOCKED)?;
    let proof = SecretProof::recovery_kit(&settings, &recovery_kit)?;
    drop(recovery_kit);
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_mut().ok_or(LOCKED)?;
    complete_recovery_setup_with(session, &proof)
}

pub fn unlock_recovery_vault_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
    recovery_kit: Zeroizing<String>,
) -> VaultResult<VaultSnapshot> {
    let turn = begin_unlock(state);
    let (snapshot, _) = unlock_with_derived_key(state, effects, &turn, |file| {
        sesame_core::api::unwrap_key_with_recovery_kit(file, &recovery_kit)
    })?;
    drop(recovery_kit);
    confirm_unlock_survived(state, &turn)?;
    drop(turn);
    let _ = establish_pin_throttle_state(state, effects);
    Ok(snapshot)
}

pub fn set_unlock_pin_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
    pin: String,
) -> VaultResult<()> {
    let pin = Zeroizing::new(pin);
    validate_new_unlock_pin(&pin)?;
    key_settings_in_state(state, SET_PIN_LOCKED)?;
    let wrap = NewPinWrap::prepare(&pin)?;
    drop(pin);
    apply_unlock_pin_in_state(state, effects, &wrap)
}

const SET_PIN_LOCKED: &str = "Unlock your vault before setting a PIN.";

pub fn apply_unlock_pin_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
    wrap: &NewPinWrap,
) -> VaultResult<()> {
    {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
        let session = session.as_mut().ok_or(SET_PIN_LOCKED)?;
        set_pin_with(session, wrap)?;
        state.pause_for_test("pinSaved");
        state.cache_pin_unlock(true);
    }
    let _ = crate::application::unlock::establish_pin_throttle_state(state, effects);
    Ok(())
}

pub fn remove_unlock_pin_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
) -> VaultResult<()> {
    {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
        let session = session
            .as_mut()
            .ok_or("Unlock your vault before removing the PIN.")?;
        remove_pin_for_session(session)?;
        state.cache_pin_unlock(false);
    }
    crate::application::unlock::discard_pin_throttle_state(state, effects);
    Ok(())
}

pub fn enable_windows_hello_in_state(state: &VaultState) -> VaultResult<()> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before turning on Windows Hello unlock.")?;
    let key_name = format!("{HELLO_KEY_NAME_PREFIX}{}", random_id());
    let material =
        session.expose_vault_key(|key| windows_hello::create_and_wrap(&key_name, key))?;
    let wrap = HelloWrap {
        key_name: material.key_name,
        ciphertext: URL_SAFE_NO_PAD.encode(material.ciphertext),
    };
    set_hello_for_session(session, wrap)?;
    state.cache_hello_unlock(true);
    Ok(())
}

pub fn disable_windows_hello_in_state(state: &VaultState) -> VaultResult<()> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before turning off Windows Hello unlock.")?;
    remove_hello_for_session(session)?;
    state.cache_hello_unlock(false);
    Ok(())
}

/// A stale Hello wrap is caught by the payload's own authenticated encryption, like a wrong password.
pub fn unlock_with_windows_hello_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
) -> VaultResult<VaultSnapshot> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not open the vault session.".to_string())?;
    let path = effects.vault_path()?;
    let file = sesame_core::loader::VaultLoader::read(&path)?;
    let wrap = file
        .hello_wrap
        .as_ref()
        .ok_or("This vault does not have Windows Hello unlock set up.")?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&wrap.ciphertext)
        .map_err(|_| "The Windows Hello unlock data for this vault is invalid.".to_string())?;
    let mut key_array = windows_hello::open_and_unwrap(&wrap.key_name, &ciphertext)?;
    let result = install_unlocked_session(state, &mut session, path, key_array, file, effects)
        .map_err(|_| {
            "Windows Hello unlock no longer matches this vault. Use your master password or recovery kit."
                .to_string()
        });
    key_array.zeroize();
    drop(session);
    if result.is_ok() {
        let _ = crate::application::unlock::establish_pin_throttle_state(state, effects);
    }
    result.map(|(snapshot, _)| snapshot)
}

pub fn unlock_pin_vault_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
    pin: String,
) -> VaultResult<VaultSnapshot> {
    let mut pin = pin;
    let result = unlock_pin_vault_inner(state, effects, &pin);
    pin.zeroize();
    result
}

fn unlock_pin_vault_inner(
    state: &VaultState,
    effects: &dyn DesktopEffects,
    pin: &str,
) -> VaultResult<VaultSnapshot> {
    // A malformed PIN is rejected before the attempt budget is touched.
    validate_unlock_pin(pin)?;
    ensure_pin_throttle_loaded(state, effects)?;
    let turn = begin_unlock(state);
    charge_pin_attempt(state, effects)?;
    let (snapshot, _) = unlock_with_derived_key(state, effects, &turn, |file| {
        let pin_wrap = file
            .pin_wrap
            .as_ref()
            .ok_or("This vault does not have a PIN set up.")?;
        let wrapping_key = Zeroizing::new(derive_pin_wrapping_key(pin, pin_wrap)?);
        let vault_key = decrypt_bytes(&wrapping_key, &pin_wrap.key_wrap, PIN_WRAP_AAD)
            .map_err(|_| "That PIN is not correct.".to_string())?;
        let key_array: [u8; 32] = vault_key
            .as_slice()
            .try_into()
            .map_err(|_| "The local vault key is invalid.".to_string())?;
        Ok(key_array)
    })?;
    if let Ok(mut guard) = state.pin_guard.lock() {
        guard.record_success();
        let _ = effects.write_pin_throttle_state(&guard);
    }
    confirm_unlock_survived(state, &turn)?;
    drop(turn);
    Ok(snapshot)
}

fn charge_pin_attempt(state: &VaultState, effects: &dyn DesktopEffects) -> VaultResult<()> {
    let mut guard = state
        .pin_guard
        .lock()
        .map_err(|_| "Sesame could not read the PIN protection state.".to_string())?;
    guard.check().map_err(|seconds| {
        format!("Too many incorrect PIN attempts. Wait {seconds} seconds, then try again.")
    })?;
    guard.record_failure();
    effects.write_pin_throttle_state(&guard).map_err(|_| {
        "Sesame could not record this PIN attempt. Use your master password instead.".to_string()
    })
}

fn ensure_pin_throttle_loaded(state: &VaultState, effects: &dyn DesktopEffects) -> VaultResult<()> {
    let mut guard = state
        .pin_guard
        .lock()
        .map_err(|_| "Sesame could not read the PIN protection state.".to_string())?;
    if state.pin_throttle_loaded() {
        return Ok(());
    }
    let persisted = effects.read_pin_throttle_state()?.ok_or_else(|| {
        "Sesame cannot verify how many PIN attempts have been made. Unlock with your master password or recovery kit to re-enable the PIN."
            .to_string()
    })?;
    *guard = PinAttemptGuard::from_persisted(persisted);
    state.mark_pin_throttle_loaded();
    Ok(())
}

pub fn retire_unlock_methods_after_key_rotation(state: &VaultState, effects: &dyn DesktopEffects) {
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    crate::application::unlock::discard_pin_throttle_state(state, effects);
    effects.discard_recovery_replacement();
    state.advance_session_epoch();
}

pub fn change_master_password_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
    request: ChangeMasterPasswordRequest,
) -> VaultResult<ChangeMasterPasswordResult> {
    const LOCKED: &str = "Unlock your vault before changing its master password.";
    let current_password = request.current_password.map(Zeroizing::new);
    let recovery_kit = request.recovery_kit.map(Zeroizing::new);
    let new_password = Zeroizing::new(request.new_password);
    let settings = key_settings_in_state(state, LOCKED)?;
    let proofs = prove_rotation_credentials(
        &settings,
        RotationCredentials {
            current_password: current_password.as_deref().map(String::as_str),
            recovery_kit: recovery_kit.as_deref().map(String::as_str),
        },
        &new_password,
    )?;
    drop(current_password);
    drop(recovery_kit);
    {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
        proofs.confirm(session.as_ref().ok_or(LOCKED)?)?;
    }
    let wraps = NewKeyWraps::derive(&new_password)?;
    drop(new_password);
    state.pause_for_test("passwordChangeDerived");
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
    let session = session.as_mut().ok_or(LOCKED)?;
    let rotation = commit_master_password_rotation(session, &proofs, &wraps)?;
    retire_unlock_methods_after_key_rotation(state, effects);
    crate::application::release_record::open_release_record(state, session);
    effects.report_key_page_fallback(session);
    Ok(ChangeMasterPasswordResult {
        recovery_kit: rotation.recovery_kit,
        backups_remaining: rotation.backups_remaining,
    })
}

pub fn record_activity() {
    crate::session_activity::record_activity();
}

pub fn set_auto_lock_minutes_in_state(state: &VaultState, minutes: u64) -> VaultResult<()> {
    if !(1..=60).contains(&minutes) {
        return Err("Choose an automatic lock delay between 1 and 60 minutes.".into());
    }
    state.set_auto_lock_minutes(minutes);
    Ok(())
}

pub fn accept_rollback_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
) -> VaultResult<()> {
    let snapshot = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?
        .as_ref()
        .map(|unlocked| unlocked.snapshot())
        .ok_or("Unlock your vault first.")?;
    let vault_id = snapshot
        .vault_id
        .ok_or("This vault has no revision record to reset.")?;
    effects.reset_rollback_record(&vault_id, snapshot.revision)
}

pub const OLDER_BACKUP_PREFIX: &str = "olderBackup:";

pub fn require_older_confirmation(
    restored_revision: u64,
    replaced_revision: Option<u64>,
    confirmed: bool,
) -> VaultResult<()> {
    match replaced_revision {
        Some(replaced) if restored_revision < replaced && !confirmed => Err(format!(
            "{OLDER_BACKUP_PREFIX}{restored_revision}:{replaced}"
        )),
        _ => Ok(()),
    }
}
