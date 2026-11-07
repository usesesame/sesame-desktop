use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::application::release::require_release_presence;
use crate::application::unlock::retire_unlock_methods_after_key_rotation;
use crate::application::DesktopEffects;
use crate::release::ReleasePresence;
use crate::vault::backup::RECOVERY_REPLACEMENT_FILE;
use crate::vault::storage::{
    atomic_replace, open_recovery_replacement_request, recovery_replacement_ready,
    replace_recovery_kit_for_session, seal_recovery_replacement_request, VaultKeyRotation,
    RECOVERY_REPLACEMENT_DELAY_SECS,
};
use crate::vault::types::CipherBlob;
use crate::vault::util::read_file_with_limit;
use crate::vault::{UnlockedVault, VaultResult, VaultState};

const MAX_REQUEST_BYTES: u64 = 4 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredRequest {
    vault_id: String,
    sealed: CipherBlob,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReplacementStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_at: Option<u64>,
    pub ready: bool,
    pub time_confirmed: bool,
}

#[derive(Serialize, Debug, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReplacementResult {
    pub recovery_kit: String,
    pub backups_remaining: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TrustedTime {
    pub earliest: u64,
    pub latest: u64,
}

pub(crate) fn request_path(vault: &Path) -> VaultResult<PathBuf> {
    let parent = vault
        .parent()
        .ok_or("Sesame could not locate the vault folder.")?;
    Ok(parent.join(RECOVERY_REPLACEMENT_FILE))
}

pub(crate) fn remove_request(path: &Path) -> VaultResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not cancel the recovery kit request.".into()),
    }
}

fn read_request(path: &Path, session: &UnlockedVault) -> VaultResult<Option<(Vec<u8>, u64)>> {
    let bytes = match read_file_with_limit(path, MAX_REQUEST_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Sesame could not read the recovery kit request.".into()),
    };
    let current_id = session.snapshot().vault_id;
    let opened = serde_json::from_slice::<StoredRequest>(&bytes)
        .ok()
        .filter(|stored| current_id.as_deref() == Some(stored.vault_id.as_str()))
        .and_then(|stored| open_recovery_replacement_request(session, &stored.sealed).ok());
    match opened {
        Some(requested_at) => Ok(Some((bytes, requested_at))),
        None => {
            remove_request(path)?;
            Ok(None)
        }
    }
}

pub(super) fn pending_request(path: &Path, session: &UnlockedVault) -> VaultResult<Option<u64>> {
    Ok(read_request(path, session)?.map(|(_, requested_at)| requested_at))
}

pub(super) fn write_request(
    path: &Path,
    session: &UnlockedVault,
    requested_at: u64,
) -> VaultResult<()> {
    if !session.setup_complete {
        return Err("Finish recovery setup before requesting a new recovery kit.".into());
    }
    let stored = StoredRequest {
        vault_id: session
            .snapshot()
            .vault_id
            .ok_or("This vault has no identifier, so a new recovery kit cannot be requested.")?,
        sealed: seal_recovery_replacement_request(session, requested_at)?,
    };
    let bytes = serde_json::to_vec(&stored)
        .map_err(|_| "Sesame could not save the recovery kit request.".to_string())?;
    atomic_replace(path, &bytes)
}

pub(super) fn complete_request(
    path: &Path,
    session: &mut UnlockedVault,
    master_password: &str,
    now: u64,
    prune_backups: bool,
) -> VaultResult<VaultKeyRotation> {
    let (stored, requested_at) =
        read_request(path, session)?.ok_or("There is no recovery kit request to complete.")?;
    if !session.setup_complete || !recovery_replacement_ready(requested_at, now) {
        return Err("The new recovery kit is not ready yet.".into());
    }
    remove_request(path)?;
    replace_recovery_kit_for_session(session, master_password, requested_at, now, prune_backups)
        .inspect_err(|_| {
            let _ = atomic_replace(path, &stored);
        })
}

pub(crate) fn pending_recovery_replacement_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
) -> VaultResult<Option<u64>> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    pending_request(&effects.recovery_replacement_path()?, session)
}

pub(crate) fn begin_recovery_replacement_request_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    effects: &dyn DesktopEffects,
) -> VaultResult<Option<u64>> {
    require_release_presence(state, presence)?;
    pending_recovery_replacement_in_state(state, effects)
}

pub(crate) fn begin_recovery_replacement_completion_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    effects: &dyn DesktopEffects,
) -> VaultResult<()> {
    require_release_presence(state, presence)?;
    pending_recovery_replacement_in_state(state, effects)?
        .ok_or_else(|| "There is no recovery kit request to complete.".to_string())?;
    Ok(())
}

pub(crate) fn write_recovery_replacement_request_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
    requested_at: u64,
) -> VaultResult<()> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    write_request(&effects.recovery_replacement_path()?, session, requested_at)
}

pub(crate) fn cancel_recovery_replacement_in_state(
    state: &VaultState,
    effects: &dyn DesktopEffects,
) -> VaultResult<()> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    session.as_ref().ok_or("Unlock your vault first.")?;
    remove_request(&effects.recovery_replacement_path()?)
}

pub(crate) fn complete_recovery_replacement_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    effects: &dyn DesktopEffects,
    master_password: Zeroizing<String>,
    now: u64,
    prune_backups: bool,
) -> VaultResult<RecoveryReplacementResult> {
    let rotation = {
        let epoch = state.session_epoch();
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the vault session.".to_string())?;
        let session = session.as_mut().ok_or("Unlock your vault first.")?;
        presence.grant_with_password(session, epoch, &master_password)?;
        complete_request(
            &effects.recovery_replacement_path()?,
            session,
            &master_password,
            now,
            prune_backups,
        )?
    };
    retire_unlock_methods_after_key_rotation(state, effects);
    Ok(RecoveryReplacementResult {
        recovery_kit: rotation.recovery_kit,
        backups_remaining: rotation.backups_remaining,
    })
}

pub(crate) fn recovery_replacement_status(
    requested_at: Option<u64>,
    confirmed: Option<TrustedTime>,
) -> RecoveryReplacementStatus {
    let Some(requested_at) = requested_at else {
        return RecoveryReplacementStatus::default();
    };
    RecoveryReplacementStatus {
        requested_at: Some(requested_at),
        available_at: Some(requested_at.saturating_add(RECOVERY_REPLACEMENT_DELAY_SECS)),
        ready: confirmed
            .is_some_and(|time| recovery_replacement_ready(requested_at, time.earliest)),
        time_confirmed: confirmed.is_some(),
    }
}
