use serde::Serialize;
use tauri::AppHandle;
use zeroize::Zeroize;

use super::sync::local_data_dir;
use crate::vault::crypto::{bytes_match, default_kdf_params, derive_key, encrypt_bytes};
use crate::vault::util::generate_recovery_kit;
use crate::vault::{VaultState, RECOVERY_WRAP_AAD, WRAP_AAD};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncAdoptResult {
    pub entry_count: usize,
    pub revision: u64,
    pub recovery_kit: String,
}

pub(super) fn verify_master_password(
    vault: &crate::vault::UnlockedVault,
    master_password: &str,
) -> Result<(), String> {
    let mut confirmed = crate::vault::crypto::unwrap_with_password(
        master_password,
        &vault.kdf,
        &vault.key_wrap,
        WRAP_AAD,
    )?
    .ok_or("That master password is not correct.")?;
    let matches = vault.expose_vault_key(|key| Ok(bytes_match(confirmed.as_slice(), key)))?;
    confirmed.zeroize();
    if !matches {
        return Err("That master password is not correct.".into());
    }
    Ok(())
}

pub(super) fn finish_adoption(
    app: &AppHandle,
    state: &tauri::State<'_, VaultState>,
    key: [u8; 32],
    payload: crate::vault::types::VaultPayload,
    master_password: &str,
    vault_id: &str,
) -> Result<String, String> {
    let recovery_kit = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session
            .as_mut()
            .ok_or("Unlock Sesame before joining a synced vault.")?;
        verify_master_password(vault, master_password)?;
        let current = vault.open_payload()?;
        let local = serde_json::to_vec(&*current)
            .map_err(|_| "Sesame could not read the local vault.".to_string())?;
        let directory = crate::sync::conflict_backup::backup_dir(&local_data_dir(app)?);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
            .to_string();
        let written = crate::sync::conflict_backup::write_verified(
            &directory,
            vault,
            crate::sync::conflict_backup::Side::ThisDevice,
            0,
            &local,
            &stamp,
        )?;
        crate::sync::conflict_backup::prune_and_report(app, &directory, &[written]);
        let _ = vault_id;
        let recovery_kit = adopt(vault, key, payload, master_password)?;
        state.advance_session_epoch();
        recovery_kit
    };
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    crate::commands::lifecycle::discard_pin_throttle_state(app, state);
    crate::browser_fill::cancel_pending_approvals(app);
    Ok(recovery_kit)
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
    let stale_hello = vault.hello_wrap.take();
    let previous = (
        std::mem::replace(&mut vault.kdf, kdf),
        std::mem::replace(&mut vault.key_wrap, key_wrap),
        std::mem::replace(&mut vault.recovery_kdf, Some(recovery_kdf)),
        std::mem::replace(&mut vault.recovery_wrap, Some(recovery_wrap)),
        std::mem::replace(&mut vault.pin_wrap, None),
        stale_hello,
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
        vault.hello_wrap = previous.5;
        vault.replace_vault_key(previous.6);
        return Err(error);
    }
    if let Some(old) = previous.5 {
        crate::vault::windows_hello::delete_key(&old.key_name);
    }
    Ok(shown)
}
