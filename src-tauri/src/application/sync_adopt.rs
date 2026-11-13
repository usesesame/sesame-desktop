use zeroize::Zeroize;

use crate::application::sync::{prepare_recovery, verify_master_password, SyncStore};
use crate::application::sync_recovery::backup_stamp;
use crate::application::DesktopEffects;
use crate::vault::crypto::{derive_key, encrypt_bytes, master_password_kdf_params};
use crate::vault::{UnlockedVault, VaultPayload, VaultState, WRAP_AAD};

pub(crate) fn finish_adoption_in_state(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
    key: [u8; 32],
    payload: VaultPayload,
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
        let directory = store.backup_dir();
        let stamp = backup_stamp();
        let written = crate::sync::conflict_backup::write_verified(
            &directory,
            vault,
            crate::sync::conflict_backup::Side::ThisDevice,
            0,
            &local,
            &stamp,
        )?;
        crate::application::sync_recovery::prune_and_report(effects, &directory, &[written]);
        let _ = vault_id;
        let recovery_kit = adopt(vault, key, payload, master_password)?;
        effects.report_key_page_fallback(vault);
        state.advance_session_epoch();
        recovery_kit
    };
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    crate::application::unlock::discard_pin_throttle_state(state, effects);
    effects.cancel_pending_approvals();
    Ok(recovery_kit)
}

pub(crate) fn digest_after_commit(payload: &VaultPayload) -> Result<String, String> {
    let mut committed = payload.clone();
    committed.revision = committed.revision.saturating_add(1);
    let mut bytes = serde_json::to_vec(&committed)
        .map_err(|_| "Sesame could not read the synced vault.".to_string())?;
    let digest = crate::sync::state::payload_digest(&bytes);
    bytes.zeroize();
    committed.zeroize();
    Ok(digest)
}

pub(crate) fn digest_kept_through_adoption(
    state: &crate::sync::state::SyncState,
    vault: &UnlockedVault,
    adopted_digest: Option<&str>,
) -> Result<Option<String>, String> {
    let payload = vault.open_payload()?;
    let mut bytes = serde_json::to_vec(&*payload)
        .map_err(|_| "Sesame could not read the local vault.".to_string())?;
    let digest = crate::sync::state::payload_digest(&bytes);
    let unchanged = state.payload_digest == digest || adopted_digest == Some(digest.as_str());
    bytes.zeroize();
    if !unchanged {
        return Ok(None);
    }
    digest_after_commit(&payload).map(Some)
}

pub(crate) struct KeptThroughAdoption {
    digest: Option<String>,
    names: std::collections::BTreeMap<String, String>,
}

impl KeptThroughAdoption {
    pub(crate) fn capture(
        state: &crate::sync::state::SyncState,
        list: &crate::sync::devicelist::DeviceList,
        vault: &UnlockedVault,
        adopted_digest: Option<&str>,
    ) -> Result<Self, String> {
        let names = vault.expose_vault_key(|key| {
            Ok(crate::application::sync::names_for(
                list,
                &state.remembered_names(),
                &state.vault_id,
                Some(key),
            ))
        })?;
        Ok(Self {
            digest: digest_kept_through_adoption(state, vault, adopted_digest)?,
            names,
        })
    }

    pub(crate) fn cleaned(&self) -> bool {
        self.digest.is_some()
    }

    pub(crate) fn adopted_payload_digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    pub(crate) fn apply(self, next: &mut crate::sync::state::SyncState) {
        if let Some(digest) = self.digest {
            next.payload_digest = digest;
        }
        let _ = next.remember_names(&self.names);
    }
}

pub(crate) fn adopt(
    vault: &mut UnlockedVault,
    key: [u8; 32],
    payload: VaultPayload,
    master_password: &str,
) -> Result<String, String> {
    adopt_with(vault, key, payload, master_password, None)?
        .ok_or_else(|| "Sesame could not prepare a recovery kit.".to_string())
}

/// Old-key wraps are rebuilt or dropped; a stale PIN wrap would unlock a vault this one cannot read.
/// With a prepared recovery wrap the kit the person already saved stays valid and no new one is made.
pub(crate) fn adopt_with(
    vault: &mut UnlockedVault,
    mut key: [u8; 32],
    payload: VaultPayload,
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
        vault.recovery_kdf.replace(recovery_kdf),
        vault.recovery_wrap.replace(recovery_wrap),
        vault.pin_wrap.take(),
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
