use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::application::sync::{SyncStore, SyncTransferResult};
use crate::application::DesktopEffects;
use crate::vault::VaultState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncBackupView {
    pub name: String,
    pub side: String,
    pub revision: i64,
    pub entry_count: usize,
    pub created_at: String,
}

pub(crate) fn backup_stamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    format!("{seconds}")
}

pub(crate) fn prune_and_report(
    effects: &dyn DesktopEffects,
    directory: &Path,
    keep: &[PathBuf],
) -> usize {
    let pruned = crate::sync::conflict_backup::prune_counting(directory, keep);
    if pruned.failed > 0 {
        effects.report_backup_io_error();
    }
    pruned.removed
}

pub(crate) fn list_conflict_backups_in_state(
    state: &VaultState,
    store: &SyncStore,
) -> Result<Vec<SyncBackupView>, String> {
    let directory = store.backup_dir();
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
    let vault = session
        .as_ref()
        .ok_or("Unlock Sesame to see your recovery copies.")?;
    vault.expose_vault_key(|key| {
        Ok(crate::sync::conflict_backup::list(&directory, key)
            .into_iter()
            .map(|entry| SyncBackupView {
                name: entry.file_name,
                side: entry.side,
                revision: entry.revision,
                entry_count: entry.entry_count,
                created_at: entry.created_at,
            })
            .collect())
    })
}

pub(crate) fn restore_conflict_backup_in_state(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
    name: &str,
) -> Result<SyncTransferResult, String> {
    if name.is_empty()
        || name.len() > 128
        || name.contains(['/', '\\', ':'])
        || name.contains("..")
        || !name.ends_with(".sesame")
    {
        return Err("That recovery copy could not be found.".into());
    }
    let directory = store.backup_dir();
    let path = directory.join(name);
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
    let vault = session
        .as_mut()
        .ok_or("Unlock Sesame before restoring a recovery copy.")?;
    let contents =
        vault.expose_vault_key(|key| crate::sync::conflict_backup::read_verified(&path, key))?;
    let payload = contents.payload.payload().clone();
    let entry_count = payload.entries.len();
    let current = vault.open_payload()?;
    let current_payload = serde_json::to_vec(&*current)
        .map_err(|_| "Sesame could not read the local vault.".to_string())?;
    let written = crate::sync::conflict_backup::write_verified(
        &directory,
        vault,
        crate::sync::conflict_backup::Side::ThisDevice,
        contents.revision,
        &current_payload,
        &backup_stamp(),
    )?;
    crate::vault::storage::commit_payload_change(vault, payload)?;
    state.advance_session_epoch();
    drop(session);
    effects.cancel_pending_approvals();
    if let Some(mut synced) = store.load_state()? {
        synced.payload_digest = String::new();
        store.save_state(&synced)?;
    }
    prune_and_report(effects, &directory, &[written]);
    Ok(SyncTransferResult {
        revision: contents.revision,
        vault_epoch: 0,
        entry_count,
    })
}
