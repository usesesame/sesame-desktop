use serde::Serialize;
use tauri::AppHandle;
use zeroize::Zeroize;

use super::sync::local_data_dir;
use crate::vault::crypto::{
    bytes_match, default_kdf_params, derive_key, encrypt_bytes, master_password_kdf_params,
};
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
        crate::vault::report_key_page_fallback(app, vault);
        state.advance_session_epoch();
        recovery_kit
    };
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    crate::commands::lifecycle::discard_pin_throttle_state(app, state);
    crate::browser_fill::cancel_pending_approvals(app);
    Ok(recovery_kit)
}

pub(super) fn prepare_recovery(
    key: &[u8; 32],
) -> Result<(String, crate::sync::key_change::PreparedRecovery), String> {
    let kit = generate_recovery_kit()?;
    let kdf = default_kdf_params();
    let wrapping_key = zeroize::Zeroizing::new(derive_key(&kit, &kdf)?);
    let wrap = encrypt_bytes(&wrapping_key, key, RECOVERY_WRAP_AAD)?;
    Ok((kit, crate::sync::key_change::PreparedRecovery { wrap, kdf }))
}

pub(super) fn adopt(
    vault: &mut crate::vault::UnlockedVault,
    key: [u8; 32],
    payload: crate::vault::types::VaultPayload,
    master_password: &str,
) -> Result<String, String> {
    adopt_with(vault, key, payload, master_password, None)?
        .ok_or_else(|| "Sesame could not prepare a recovery kit.".to_string())
}

/// Old-key wraps are rebuilt or dropped; a stale PIN wrap would unlock a vault this one cannot read.
/// With a prepared recovery wrap the kit the person already saved stays valid and no new one is made.
pub(super) fn adopt_with(
    vault: &mut crate::vault::UnlockedVault,
    mut key: [u8; 32],
    payload: crate::vault::types::VaultPayload,
    master_password: &str,
    prepared: Option<crate::sync::key_change::PreparedRecovery>,
) -> Result<Option<String>, String> {
    let kdf = master_password_kdf_params();
    let wrapping_key = zeroize::Zeroizing::new(derive_key(master_password, &kdf)?);
    let key_wrap = encrypt_bytes(&wrapping_key, &key, WRAP_AAD)?;

    let (shown, recovery_wrap, recovery_kdf) = match prepared {
        Some(prepared) => (None, prepared.wrap, prepared.kdf),
        None => {
            let (kit, recovery) = prepare_recovery(&key)?;
            (Some(kit), recovery.wrap, recovery.kdf)
        }
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::decrypt_bytes;
    use crate::vault::UnlockedVault;
    use sesame_core::api::create_vault;

    const PASSWORD: &str = "fictional master password";

    fn session() -> UnlockedVault {
        let (opened, _) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
        let directory =
            std::env::temp_dir().join(format!("sesame-adopt-{}", crate::vault::random_id()));
        std::fs::create_dir_all(&directory).expect("directory");
        let path = directory.join("vault.sesame");
        UnlockedVault::from_opened(path, &opened).expect("unlocked vault")
    }

    fn recovery_opens(vault: &UnlockedVault, kit: &str, key: &[u8; 32]) -> bool {
        let (Some(kdf), Some(wrap)) = (&vault.recovery_kdf, &vault.recovery_wrap) else {
            return false;
        };
        let wrapping = derive_key(kit, kdf).expect("derived");
        decrypt_bytes(&wrapping, wrap, RECOVERY_WRAP_AAD)
            .is_ok_and(|opened| opened.as_slice() == key.as_slice())
    }

    #[test]
    fn a_prepared_kit_stays_valid_after_adoption_and_no_second_kit_is_made() {
        let mut vault = session();
        let payload = vault.open_payload().expect("payload").clone();
        let key = [7u8; 32];
        let (kit, recovery) = prepare_recovery(&key).expect("prepared");

        let shown = adopt_with(
            &mut vault,
            key,
            payload.clone(),
            PASSWORD,
            Some(recovery.clone()),
        )
        .expect("adopted");
        assert!(shown.is_none());
        assert!(recovery_opens(&vault, &kit, &key));
        assert!(!recovery_opens(
            &vault,
            "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA",
            &key
        ));

        let again =
            adopt_with(&mut vault, key, payload, PASSWORD, Some(recovery)).expect("adopted again");
        assert!(again.is_none());
        assert!(
            recovery_opens(&vault, &kit, &key),
            "adopting twice from the journal keeps the saved kit working"
        );
    }

    #[test]
    fn without_a_prepared_kit_adoption_makes_one_that_opens_the_new_key() {
        let mut vault = session();
        let payload = vault.open_payload().expect("payload").clone();
        let key = [9u8; 32];
        let kit = adopt_with(&mut vault, key, payload, PASSWORD, None)
            .expect("adopted")
            .expect("a kit");
        assert!(recovery_opens(&vault, &kit, &key));
    }

    #[test]
    fn a_kit_prepared_for_one_key_does_not_open_another() {
        let (kit, recovery) = prepare_recovery(&[1u8; 32]).expect("prepared");
        let wrapping = derive_key(&kit, &recovery.kdf).expect("derived");
        let opened = decrypt_bytes(&wrapping, &recovery.wrap, RECOVERY_WRAP_AAD).expect("opens");
        assert_eq!(opened.as_slice(), [1u8; 32].as_slice());
        assert!(decrypt_bytes(&wrapping, &recovery.wrap, WRAP_AAD).is_err());
    }
}
