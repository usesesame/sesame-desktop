use zeroize::Zeroize;

use crate::application::sync::{
    confirm_master_password, master_password_proof, prepare_recovery, SyncStore,
};
use crate::application::sync_recovery::backup_stamp;
use crate::application::DesktopEffects;
use crate::sync::state::StateNames;
use crate::vault::key_proof::NewMasterWrap;
use crate::vault::{UnlockedVault, VaultPayload, VaultState};

pub fn finish_adoption_in_state(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
    key: [u8; 32],
    payload: VaultPayload,
    master_password: &str,
    vault_id: &str,
) -> Result<String, String> {
    const LOCKED: &str = "Unlock Sesame before joining a synced vault.";
    let proof = master_password_proof(state, master_password, LOCKED)?;
    {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        confirm_master_password(session.as_ref().ok_or(LOCKED)?, &proof)?;
    }
    let wraps = AdoptionWraps::seal(key, master_password, None)?;
    let recovery_kit = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let vault = session.as_mut().ok_or(LOCKED)?;
        confirm_master_password(vault, &proof)?;
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
        let recovery_kit = adopt_prepared(vault, wraps, payload)?
            .ok_or_else(|| "Sesame could not prepare a recovery kit.".to_string())?;
        crate::application::release_record::open_release_record(state, vault);
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

pub fn digest_after_commit(payload: &VaultPayload) -> Result<String, String> {
    crate::sync::state::change_digest(payload)
}

pub fn digest_kept_through_adoption(
    state: &crate::sync::state::SyncState,
    vault: &UnlockedVault,
    adopted_digests: [Option<&str>; 2],
) -> Result<Option<String>, String> {
    let payload = vault.open_payload()?;
    let mut unchanged = !state.has_local_changes(&payload)?;
    for adopted in adopted_digests.into_iter().flatten() {
        unchanged = unchanged || crate::sync::state::digest_describes(adopted, &payload)?;
    }
    if !unchanged {
        return Ok(None);
    }
    digest_after_commit(&payload).map(Some)
}

pub struct KeptThroughAdoption {
    digest: Option<String>,
    names: std::collections::BTreeMap<String, String>,
}

impl KeptThroughAdoption {
    pub fn capture(
        state: &crate::sync::state::SyncState,
        list: &crate::sync::devicelist::DeviceList,
        vault: &UnlockedVault,
        adopted_digests: [Option<&str>; 2],
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
            digest: digest_kept_through_adoption(state, vault, adopted_digests)?,
            names,
        })
    }

    pub fn cleaned(&self) -> bool {
        self.digest.is_some()
    }

    pub fn adopted_payload_digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    pub fn names(&self) -> &std::collections::BTreeMap<String, String> {
        &self.names
    }

    pub fn apply(self, next: &mut crate::sync::state::SyncState) {
        if let Some(digest) = self.digest {
            next.payload_digest = digest;
        }
        let _ = next.remember_names(&self.names);
    }
}

pub fn adopt(
    vault: &mut UnlockedVault,
    key: [u8; 32],
    payload: VaultPayload,
    master_password: &str,
) -> Result<String, String> {
    adopt_with(vault, key, payload, master_password, None)?
        .ok_or_else(|| "Sesame could not prepare a recovery kit.".to_string())
}

pub struct AdoptionWraps {
    key: zeroize::Zeroizing<[u8; 32]>,
    kdf: crate::vault::KdfParams,
    key_wrap: crate::vault::CipherBlob,
    recovery: crate::sync::key_change::PreparedRecovery,
    shown: Option<String>,
}

impl AdoptionWraps {
    pub fn seal(
        key: [u8; 32],
        master_password: &str,
        prepared: Option<crate::sync::key_change::PreparedRecovery>,
    ) -> Result<Self, String> {
        let key = zeroize::Zeroizing::new(key);
        let (kdf, key_wrap) = NewMasterWrap::derive(master_password)?.seal(&key)?;
        let (shown, recovery) = match prepared {
            Some(prepared) => (None, prepared),
            None => {
                let (kit, recovery) = prepare_recovery(&key)?;
                (Some(kit), recovery)
            }
        };
        Ok(Self {
            key,
            kdf,
            key_wrap,
            recovery,
            shown,
        })
    }
}

/// Old-key wraps are rebuilt or dropped; a stale PIN wrap would unlock a vault this one cannot read.
/// With a prepared recovery wrap the kit the person already saved stays valid and no new one is made.
pub fn adopt_with(
    vault: &mut UnlockedVault,
    key: [u8; 32],
    payload: VaultPayload,
    master_password: &str,
    prepared: Option<crate::sync::key_change::PreparedRecovery>,
) -> Result<Option<String>, String> {
    adopt_prepared(
        vault,
        AdoptionWraps::seal(key, master_password, prepared)?,
        payload,
    )
}

pub fn adopt_prepared(
    vault: &mut UnlockedVault,
    wraps: AdoptionWraps,
    payload: VaultPayload,
) -> Result<Option<String>, String> {
    let AdoptionWraps {
        key: sealed_key,
        kdf,
        key_wrap,
        recovery,
        shown,
    } = wraps;
    let mut key = *sealed_key;
    let (recovery_wrap, recovery_kdf) = (recovery.wrap, recovery.kdf);

    let next_pending = crate::vault::pending_change::stage_for_new_key(
        vault,
        &key,
        payload.vault_id.as_deref().unwrap_or_default(),
    )?;
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
        crate::vault::pending_change::abandon_new_key(vault, next_pending);
        vault.kdf = previous.0;
        vault.key_wrap = previous.1;
        vault.recovery_kdf = previous.2;
        vault.recovery_wrap = previous.3;
        vault.pin_wrap = previous.4;
        vault.hello_wrap = previous.5;
        vault.replace_vault_key(previous.6);
        return Err(error);
    }
    crate::vault::pending_change::finish_new_key(vault, next_pending);
    if let Some(old) = previous.5 {
        crate::vault::windows_hello::delete_key(&old.key_name);
    }
    Ok(shown)
}
