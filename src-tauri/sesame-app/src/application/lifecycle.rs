use std::path::PathBuf;

use zeroize::{Zeroize, Zeroizing};

use crate::application::DesktopEffects;
use crate::release::ReleasePresence;
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
    if opened.migrated {
        if let Err(error) = persist_session(&mut unlocked) {
            return Err(format!(
                "Sesame upgraded your vault but could not save the upgrade: {error}"
            ));
        }
    }
    let snapshot = unlocked.snapshot();
    effects.observe_unlock(&snapshot);
    *session = Some(unlocked);
    // Fresh session epoch invalidates approvals bound to the previous one.
    let epoch = state.advance_session_epoch();
    state.cache_pin_unlock(pin_unlock_available);
    state.cache_hello_unlock(hello_unlock_available);
    Ok((snapshot, epoch))
}

pub fn unlock_vault_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    effects: &dyn DesktopEffects,
    master_password: Zeroizing<String>,
) -> VaultResult<VaultSnapshot> {
    // One lifecycle critical section from file read to install.
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not open the vault session.".to_string())?;
    let path = effects.vault_path()?;
    let file = sesame_core::loader::VaultLoader::read(&path)?;
    let key_array = sesame_core::api::unwrap_key_with_password(&file, &master_password)?;
    let result = install_unlocked_session(state, &mut session, path, key_array, file, effects);
    drop(session);
    if let Ok((_, epoch)) = &result {
        let _ = crate::application::unlock::establish_pin_throttle_state(state, effects);
        presence.grant_after_unlock(*epoch);
    }
    result.map(|(snapshot, _)| snapshot)
}

/// The event half of locking; every lock entry point calls this so behavior cannot drift.
pub fn lock_and_notify(state: &VaultState, effects: &dyn DesktopEffects) -> VaultResult<()> {
    effects.observe_lock(state);
    state.lock_for_lifecycle()?;
    let _ = effects.clear_armed_clipboard();
    effects.revoke_presence();
    effects.cancel_breach_scan();
    effects
        .emit_vault_locked()
        .map_err(|_| "Sesame could not notify the interface that the vault locked.".to_string())?;
    Ok(())
}
