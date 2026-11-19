use std::path::PathBuf;
use std::sync::MutexGuard;

use zeroize::{Zeroize, Zeroizing};

use crate::application::DesktopEffects;
use crate::release::ReleasePresence;
use crate::vault::key_proof::KeySettings;
use crate::vault::storage::persist_session;
use crate::vault::{UnlockedVault, VaultFile, VaultResult, VaultSnapshot, VaultState};

pub fn install_unlocked_session(
    state: &VaultState,
    session: &mut Option<UnlockedVault>,
    path: PathBuf,
    mut key_array: [u8; 32],
    file: VaultFile,
    effects: &dyn DesktopEffects,
) -> VaultResult<(VaultSnapshot, u64)> {
    let opened = sesame_core::api::open_vault_with_key(&file, key_array);
    key_array.zeroize();
    let opened = opened?;
    let pin_unlock_available = opened.file.pin_wrap.is_some();
    let hello_unlock_available = opened.file.hello_wrap.is_some();
    // `OpenedVault` zeroizes on drop, so build the session without moving its fields out.
    let mut unlocked = UnlockedVault::from_opened(path, &opened)?;
    effects.report_key_page_fallback(&unlocked);
    if opened.migrated && unlocked.setup_complete {
        if let Err(error) = persist_session(&mut unlocked) {
            return Err(format!(
                "Sesame upgraded your vault but could not save the upgrade: {error}"
            ));
        }
    }
    if let Some((store, _run)) = effects.claim_idle_sync_store() {
        let _ = crate::application::sync::upgrade_legacy_digest(&store, &unlocked);
    }
    let snapshot = unlocked.snapshot();
    effects.observe_unlock(&snapshot);
    state.install_session(session, unlocked);
    if let Some(unlocked) = session.as_ref() {
        crate::application::release_record::open_release_record(state, unlocked);
    }
    // Fresh session epoch invalidates approvals bound to the previous one.
    let epoch = state.advance_session_epoch();
    state.cache_pin_unlock(pin_unlock_available);
    state.cache_hello_unlock(hello_unlock_available);
    Ok((snapshot, epoch))
}

pub const LOCKED_DURING_UNLOCK: &str =
    "Sesame locked or replaced the vault before the unlock finished. Try again.";

pub fn same_key_settings(read: &VaultFile, current: &VaultFile) -> bool {
    fn json<T: serde::Serialize>(value: &T) -> Option<Vec<u8>> {
        serde_json::to_vec(value).ok()
    }
    json(&read.kdf).is_some_and(|kdf| Some(kdf) == json(&current.kdf))
        && json(&read.key_wrap).is_some_and(|wrap| Some(wrap) == json(&current.key_wrap))
        && json(&read.recovery_kdf) == json(&current.recovery_kdf)
        && json(&read.recovery_wrap) == json(&current.recovery_wrap)
        && json(&read.pin_wrap) == json(&current.pin_wrap)
}

pub struct UnlockTurn<'a> {
    _gate: MutexGuard<'a, ()>,
    lock_generation: u64,
}

pub fn begin_unlock(state: &VaultState) -> VaultResult<UnlockTurn<'_>> {
    let lock_generation = state.lock_generation();
    state.pause_for_test("unlockQueued");
    let gate = state
        .unlock_gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.lock_generation() != lock_generation {
        return Err(LOCKED_DURING_UNLOCK.into());
    }
    Ok(UnlockTurn {
        _gate: gate,
        lock_generation,
    })
}

pub fn unlock_with_derived_key(
    state: &VaultState,
    effects: &dyn DesktopEffects,
    turn: &UnlockTurn<'_>,
    derive: impl FnOnce(&VaultFile) -> VaultResult<[u8; 32]>,
) -> VaultResult<(VaultSnapshot, u64)> {
    let epoch = state.session_epoch();
    let path = effects.vault_path()?;
    let read = sesame_core::loader::VaultLoader::read(&path)?;
    let key = Zeroizing::new(derive(&read)?);
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not open the vault session.".to_string())?;
    if state.session_epoch() != epoch || state.lock_generation() != turn.lock_generation {
        return Err(LOCKED_DURING_UNLOCK.into());
    }
    let current = sesame_core::loader::VaultLoader::read(&path)?;
    if !same_key_settings(&read, &current) {
        return Err(LOCKED_DURING_UNLOCK.into());
    }
    let installed = install_unlocked_session(state, &mut session, path, *key, current, effects);
    drop(session);
    installed
}

pub fn key_settings_in_state(state: &VaultState, locked: &str) -> VaultResult<KeySettings> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault session.".to_string())?;
    session
        .as_ref()
        .map(KeySettings::of)
        .ok_or(locked.to_string())
}

pub fn confirm_unlock_survived(state: &VaultState, turn: &UnlockTurn<'_>) -> VaultResult<()> {
    finish_unlock(state, turn, || ())
}

pub fn finish_unlock<T>(
    state: &VaultState,
    turn: &UnlockTurn<'_>,
    commit: impl FnOnce() -> T,
) -> VaultResult<T> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not open the vault session.".to_string())?;
    if session.is_some() && state.lock_generation() == turn.lock_generation {
        let committed = commit();
        drop(session);
        Ok(committed)
    } else {
        Err(LOCKED_DURING_UNLOCK.into())
    }
}

pub fn unlock_vault_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    effects: &dyn DesktopEffects,
    master_password: Zeroizing<String>,
) -> VaultResult<VaultSnapshot> {
    let turn = begin_unlock(state)?;
    let (snapshot, epoch) = unlock_with_derived_key(state, effects, &turn, |file| {
        sesame_core::api::unwrap_key_with_password(file, &master_password)
    })?;
    drop(master_password);
    finish_unlock(state, &turn, || {
        state.pause_for_test("unlockCommitting");
        let _ = crate::application::unlock::establish_pin_throttle_state(state, effects);
        presence.grant_after_unlock(epoch);
    })?;
    drop(turn);
    Ok(snapshot)
}

pub fn lock_if_unlocked(state: &VaultState, effects: &dyn DesktopEffects) -> VaultResult<bool> {
    if !state.lock_if_unlocked()? {
        return Ok(false);
    }
    lock_and_notify(state, effects)?;
    Ok(true)
}

/// The event half of locking; every lock entry point calls this so behavior cannot drift.
pub fn lock_and_notify(state: &VaultState, effects: &dyn DesktopEffects) -> VaultResult<()> {
    effects.observe_lock(state);
    state.lock_for_lifecycle()?;
    let _ = effects.clear_armed_clipboard();
    effects.revoke_presence();
    effects.forget_terminal_allowances();
    effects.cancel_breach_scan();
    effects
        .emit_vault_locked()
        .map_err(|_| "Sesame could not notify the interface that the vault locked.".to_string())?;
    Ok(())
}
