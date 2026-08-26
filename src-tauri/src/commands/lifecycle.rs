use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use tauri::{AppHandle, State};
use zeroize::{Zeroize, Zeroizing};

use crate::vault::crypto::decrypt_bytes;
use crate::vault::snapshot::snapshot_for;
use crate::vault::storage::{
    check_supported_vault_format, clear_pin_throttle_state, complete_recovery_setup_for_session,
    derive_pin_wrapping_key, persist_session, read_pin_throttle_state, remove_hello_for_session,
    remove_pin_for_session, resume_recovery_setup_for_session, set_hello_for_session,
    set_pin_for_session, validate_new_unlock_pin, validate_unlock_pin, vault_path,
    write_pin_throttle_state, write_vault_file,
};
use crate::vault::util::random_id;
use crate::vault::windows_hello;
use crate::vault::{
    ChangeMasterPasswordRequest, ChangeMasterPasswordResult, HelloWrap, MasterPasswordRequest,
    RecoveryKitRequest, UnlockPinRequest, UnlockedVault, VaultFile, VaultResult, VaultSetup,
    VaultSnapshot, VaultState, VaultStatus, HELLO_KEY_NAME_PREFIX, MAX_VAULT_FILE_BYTES,
    PIN_WRAP_AAD,
};

#[tauri::command]
pub fn get_vault_status(app: AppHandle, state: State<'_, VaultState>) -> VaultResult<VaultStatus> {
    let path = vault_path(&app)?;
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
    let (vault_id, revision, onboarding_required) = session
        .as_ref()
        .map(|s| {
            (
                s.payload.vault_id.clone(),
                s.payload.revision,
                !s.setup_complete,
            )
        })
        .unwrap_or_default();
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
    let Ok(bytes) = crate::vault::util::read_file_with_limit(path, MAX_VAULT_FILE_BYTES) else {
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
    let Ok(bytes) = crate::vault::util::read_file_with_limit(path, MAX_VAULT_FILE_BYTES) else {
        return false;
    };
    serde_json::from_slice::<StoredVaultHelloStatus>(&bytes)
        .ok()
        .and_then(|status| status.hello_wrap)
        .is_some()
}

#[tauri::command]
pub fn create_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: MasterPasswordRequest,
) -> VaultResult<VaultSetup> {
    // Crypto lives in `sesame_core::api`; this command only resolves the path and installs the session.
    let master_password = Zeroizing::new(request.master_password);
    let (opened, recovery_kit_for_display) =
        sesame_core::api::create_vault(&master_password, "My Sesame vault")?;
    drop(master_password);
    // Session guard first: a concurrent restore must not race the file creation.
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not open the vault session.".to_string())?;
    let path = vault_path(&app)?;
    if path.exists() {
        return Err("A local Sesame vault already exists on this device.".into());
    }
    write_vault_file(&path, &opened.file)?;
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    let _ = establish_pin_throttle_state(&app, &state);

    let snapshot = snapshot_for(&opened.payload);
    // `OpenedVault` zeroizes on drop, so clone and let it drop rather than moving fields out.
    *session = Some(UnlockedVault {
        path,
        key: opened.key.clone(),
        kdf: opened.file.kdf.clone(),
        key_wrap: opened.file.key_wrap.clone(),
        legacy_device_wrap: None,
        recovery_kdf: opened.file.recovery_kdf.clone(),
        recovery_wrap: opened.file.recovery_wrap.clone(),
        pin_wrap: None,
        hello_wrap: None,
        setup_complete: opened.file.setup_complete,
        payload: opened.payload.clone(),
    });
    state.advance_session_epoch();
    Ok(VaultSetup {
        snapshot,
        recovery_kit: recovery_kit_for_display,
    })
}

/// Shared unlock tail: persist any migration, install the session, advance the epoch.
fn install_unlocked_session(
    state: &State<'_, VaultState>,
    session: &mut Option<UnlockedVault>,
    path: PathBuf,
    key_array: [u8; 32],
    file: VaultFile,
) -> VaultResult<VaultSnapshot> {
    let opened = sesame_core::api::open_vault_with_key(&file, key_array)?;
    let pin_unlock_available = opened.file.pin_wrap.is_some();
    let hello_unlock_available = opened.file.hello_wrap.is_some();
    let snapshot = snapshot_for(&opened.payload);
    // Same zeroize-on-drop workaround `create_vault` uses.
    let mut unlocked = UnlockedVault {
        path,
        key: opened.key.clone(),
        kdf: opened.file.kdf.clone(),
        key_wrap: opened.file.key_wrap.clone(),
        legacy_device_wrap: opened.file.legacy_device_wrap.clone(),
        recovery_kdf: opened.file.recovery_kdf.clone(),
        recovery_wrap: opened.file.recovery_wrap.clone(),
        pin_wrap: opened.file.pin_wrap.clone(),
        hello_wrap: opened.file.hello_wrap.clone(),
        setup_complete: opened.file.setup_complete,
        payload: opened.payload.clone(),
    };
    if opened.migrated {
        if let Err(error) = persist_session(&mut unlocked) {
            return Err(format!(
                "Sesame upgraded your vault but could not save the upgrade: {error}"
            ));
        }
    }
    *session = Some(unlocked);
    // Fresh session epoch invalidates approvals bound to the previous one.
    state.advance_session_epoch();
    state.cache_pin_unlock(pin_unlock_available);
    state.cache_hello_unlock(hello_unlock_available);
    Ok(snapshot)
}

/// Replacement kit for an interrupted setup; only the still-empty pending vault can use this path.
#[tauri::command]
pub fn resume_recovery_setup(state: State<'_, VaultState>) -> VaultResult<String> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before resuming recovery setup.")?;
    resume_recovery_setup_for_session(session)
}

/// Host-owned recovery gate: a renderer preference cannot satisfy it.
#[tauri::command]
pub fn complete_recovery_setup(
    state: State<'_, VaultState>,
    request: RecoveryKitRequest,
) -> VaultResult<()> {
    let recovery_kit = Zeroizing::new(request.recovery_kit);
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before completing recovery setup.")?;
    complete_recovery_setup_for_session(session, &recovery_kit)
}

#[tauri::command]
pub fn unlock_recovery_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: RecoveryKitRequest,
) -> VaultResult<VaultSnapshot> {
    // Guard held from file read to install: restore or deletion must never race it.
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not open the vault session.".to_string())?;
    let path = vault_path(&app)?;
    let bytes = crate::vault::util::require_file_with_limit(
        &path,
        MAX_VAULT_FILE_BYTES,
        "Sesame could not find a local vault to unlock.",
    )?;
    let file: VaultFile = serde_json::from_slice(&bytes).map_err(|_| {
        "This vault file is not valid. Restore a known-good encrypted backup.".to_string()
    })?;
    check_supported_vault_format(&file)?;
    let supplied_kit = Zeroizing::new(request.recovery_kit);
    let key_array = sesame_core::api::unwrap_key_with_recovery_kit(&file, &supplied_kit)?;
    install_unlocked_session(&state, &mut session, path, key_array, file)
}

#[tauri::command]
pub fn set_unlock_pin(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: UnlockPinRequest,
) -> VaultResult<()> {
    let mut pin = request.pin;
    let result = (|| {
        validate_new_unlock_pin(&pin)?;
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
        let session = session
            .as_mut()
            .ok_or("Unlock your vault before setting a PIN.")?;
        set_pin_for_session(session, &pin)
    })();
    pin.zeroize();
    if result.is_ok() {
        let _ = establish_pin_throttle_state(&app, &state);
        state.cache_pin_unlock(true);
    }
    result
}

#[tauri::command]
pub fn remove_unlock_pin(app: AppHandle, state: State<'_, VaultState>) -> VaultResult<()> {
    {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
        let session = session
            .as_mut()
            .ok_or("Unlock your vault before removing the PIN.")?;
        remove_pin_for_session(session)?;
    }
    state.cache_pin_unlock(false);
    discard_pin_throttle_state(&app, &state);
    Ok(())
}

#[tauri::command]
pub fn enable_windows_hello(state: State<'_, VaultState>) -> VaultResult<()> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before turning on Windows Hello unlock.")?;
    let key_name = format!("{HELLO_KEY_NAME_PREFIX}{}", random_id());
    let material = windows_hello::create_and_wrap(&key_name, &session.key)?;
    let wrap = HelloWrap {
        key_name: material.key_name,
        ciphertext: URL_SAFE_NO_PAD.encode(material.ciphertext),
    };
    set_hello_for_session(session, wrap)?;
    state.cache_hello_unlock(true);
    Ok(())
}

#[tauri::command]
pub fn disable_windows_hello(state: State<'_, VaultState>) -> VaultResult<()> {
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
#[tauri::command]
pub fn unlock_with_windows_hello(
    app: AppHandle,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not open the vault session.".to_string())?;
    let path = vault_path(&app)?;
    let bytes = crate::vault::util::require_file_with_limit(
        &path,
        MAX_VAULT_FILE_BYTES,
        "Sesame could not find a local vault to unlock.",
    )?;
    let file: VaultFile = serde_json::from_slice(&bytes).map_err(|_| {
        "This vault file is not valid. Restore a known-good encrypted backup.".to_string()
    })?;
    check_supported_vault_format(&file)?;
    let wrap = file
        .hello_wrap
        .as_ref()
        .ok_or("This vault does not have Windows Hello unlock set up.")?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&wrap.ciphertext)
        .map_err(|_| "The Windows Hello unlock data for this vault is invalid.".to_string())?;
    let mut key_array = windows_hello::open_and_unwrap(&wrap.key_name, &ciphertext)?;
    let result = install_unlocked_session(&state, &mut session, path, key_array, file).map_err(
        |_| {
            "Windows Hello unlock no longer matches this vault. Use your master password or recovery kit."
                .to_string()
        },
    );
    key_array.zeroize();
    drop(session);
    if result.is_ok() {
        let _ = establish_pin_throttle_state(&app, &state);
    }
    result
}

#[tauri::command]
pub fn unlock_pin_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: UnlockPinRequest,
) -> VaultResult<VaultSnapshot> {
    let mut pin = request.pin;
    let result = unlock_pin_vault_inner(app, state, &pin);
    pin.zeroize();
    result
}

fn unlock_pin_vault_inner(
    app: AppHandle,
    state: State<'_, VaultState>,
    pin: &str,
) -> VaultResult<VaultSnapshot> {
    // A malformed PIN is rejected before the attempt budget is touched.
    validate_unlock_pin(pin)?;
    ensure_pin_throttle_loaded(&app, &state)?;
    // The attempt is spent and persisted before any slow work, under the budget lock.
    {
        let mut guard = state
            .pin_guard
            .lock()
            .map_err(|_| "Sesame could not read the PIN protection state.".to_string())?;
        guard.check().map_err(|seconds| {
            format!("Too many incorrect PIN attempts. Wait {seconds} seconds, then try again.")
        })?;
        guard.record_failure();
        write_pin_throttle_state(&app, &guard).map_err(|_| {
            "Sesame could not record this PIN attempt. Use your master password instead."
                .to_string()
        })?;
    }
    // Throttle first; the decrypt/install path stays serialized with restore and deletion.
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not open the vault session.".to_string())?;
    let path = vault_path(&app)?;
    let bytes = crate::vault::util::require_file_with_limit(
        &path,
        MAX_VAULT_FILE_BYTES,
        "Sesame could not find a local vault to unlock.",
    )?;
    let file: VaultFile = serde_json::from_slice(&bytes).map_err(|_| {
        "This vault file is not valid. Restore a known-good encrypted backup.".to_string()
    })?;
    check_supported_vault_format(&file)?;
    let pin_wrap = file
        .pin_wrap
        .as_ref()
        .ok_or("This vault does not have a PIN set up.")?;
    let wrapping_key = Zeroizing::new(derive_pin_wrapping_key(pin, pin_wrap)?);
    // The attempt was already spent and persisted above; nothing left to record here.
    let mut vault_key = decrypt_bytes(&wrapping_key, &pin_wrap.key_wrap, PIN_WRAP_AAD)
        .map_err(|_| "That PIN is not correct.".to_string())?;
    let key_array: [u8; 32] = vault_key
        .as_slice()
        .try_into()
        .map_err(|_| "The local vault key is invalid.".to_string())?;
    vault_key.zeroize();
    let result = install_unlocked_session(&state, &mut session, path, key_array, file);
    drop(session);
    if result.is_ok() {
        if let Ok(mut guard) = state.pin_guard.lock() {
            guard.record_success();
            let _ = write_pin_throttle_state(&app, &guard);
        }
    }
    result
}

fn ensure_pin_throttle_loaded(app: &AppHandle, state: &State<'_, VaultState>) -> VaultResult<()> {
    let mut guard = state
        .pin_guard
        .lock()
        .map_err(|_| "Sesame could not read the PIN protection state.".to_string())?;
    if state.pin_throttle_loaded() {
        return Ok(());
    }
    let persisted = read_pin_throttle_state(app)?.ok_or_else(|| {
        "Sesame cannot verify how many PIN attempts have been made. Unlock with your master password or recovery kit to re-enable the PIN."
            .to_string()
    })?;
    *guard = crate::vault::throttle::PinAttemptGuard::from_persisted(persisted);
    state.mark_pin_throttle_loaded();
    Ok(())
}

pub(super) fn establish_pin_throttle_state(
    app: &AppHandle,
    state: &State<'_, VaultState>,
) -> VaultResult<()> {
    let mut guard = state
        .pin_guard
        .lock()
        .map_err(|_| "Sesame could not read the PIN protection state.".to_string())?;
    guard.record_success();
    write_pin_throttle_state(app, &guard)?;
    state.mark_pin_throttle_loaded();
    Ok(())
}

pub(crate) fn discard_pin_throttle_state(app: &AppHandle, state: &State<'_, VaultState>) {
    if let Ok(mut guard) = state.pin_guard.lock() {
        guard.record_success();
        state.mark_pin_throttle_loaded();
    }
    let _ = clear_pin_throttle_state(app);
}

#[tauri::command]
pub fn unlock_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: MasterPasswordRequest,
) -> VaultResult<VaultSnapshot> {
    // One lifecycle critical section from file read to install.
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not open the vault session.".to_string())?;
    let path = vault_path(&app)?;
    let bytes = crate::vault::util::require_file_with_limit(
        &path,
        MAX_VAULT_FILE_BYTES,
        "Sesame could not find a local vault to unlock.",
    )?;
    let file: VaultFile = serde_json::from_slice(&bytes).map_err(|_| {
        "This vault file is not valid. Restore a known-good encrypted backup.".to_string()
    })?;
    check_supported_vault_format(&file)?;
    let master_password = Zeroizing::new(request.master_password);
    let key_array = sesame_core::api::unwrap_key_with_password(&file, &master_password)?;
    let result = install_unlocked_session(&state, &mut session, path, key_array, file);
    drop(session);
    if result.is_ok() {
        let _ = establish_pin_throttle_state(&app, &state);
    }
    result
}

#[tauri::command]
pub fn change_master_password(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: ChangeMasterPasswordRequest,
) -> VaultResult<ChangeMasterPasswordResult> {
    let mut current_password = request.current_password;
    let mut new_password = request.new_password;
    let result = (|| {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
        let session = session
            .as_mut()
            .ok_or("Unlock your vault before changing its master password.")?;
        let recovery_kit = crate::vault::storage::rotate_master_password_for_session(
            session,
            &current_password,
            &new_password,
        )?;
        state.cache_pin_unlock(false);
        state.cache_hello_unlock(false);
        discard_pin_throttle_state(&app, &state);
        state.advance_session_epoch();
        Ok(ChangeMasterPasswordResult { recovery_kit })
    })();
    current_password.zeroize();
    new_password.zeroize();
    result
}

#[tauri::command]
pub fn set_auto_lock_minutes(minutes: u64, state: State<'_, VaultState>) -> VaultResult<()> {
    if !(1..=60).contains(&minutes) {
        return Err("Choose an automatic lock delay between 1 and 60 minutes.".into());
    }
    state.set_auto_lock_minutes(minutes);
    Ok(())
}
