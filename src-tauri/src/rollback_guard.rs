use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

use crate::sync::state::{read_tagged, write_tagged};
use crate::vault::{VaultResult, VaultSnapshot, VaultState};

const FILE_NAME: &str = "vault-high-water.json";
const TAG_LABEL: &[u8] = b"sesame-vault-high-water-tag-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HighWater {
    pub vault_id: String,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackNotice {
    pub recorded_revision: u64,
    pub found_revision: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Unchanged,
    Raise(HighWater),
    Below(RollbackNotice),
}

pub fn judge(record: Option<&HighWater>, vault_id: &str, revision: u64) -> Verdict {
    let raised = || {
        Verdict::Raise(HighWater {
            vault_id: vault_id.to_string(),
            revision,
        })
    };
    match record {
        Some(recorded) if recorded.vault_id == vault_id => {
            if revision < recorded.revision {
                Verdict::Below(RollbackNotice {
                    recorded_revision: recorded.revision,
                    found_revision: revision,
                })
            } else if revision == recorded.revision {
                Verdict::Unchanged
            } else {
                raised()
            }
        }
        _ => raised(),
    }
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

fn record_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

pub fn read_record(data_dir: &Path) -> Option<HighWater> {
    let body = read_tagged(&record_path(data_dir), TAG_LABEL)?;
    serde_json::from_slice(&body).ok()
}

pub fn write_record(data_dir: &Path, record: &HighWater) -> VaultResult<()> {
    let body = serde_json::to_vec(record)
        .map_err(|_| "Sesame could not record the vault revision.".to_string())?;
    write_tagged(&record_path(data_dir), TAG_LABEL, &body)
}

pub fn observe(data_dir: &Path, vault_id: &str, revision: u64) -> Option<RollbackNotice> {
    match judge(read_record(data_dir).as_ref(), vault_id, revision) {
        Verdict::Unchanged => None,
        Verdict::Raise(record) => {
            let _ = write_record(data_dir, &record);
            None
        }
        Verdict::Below(notice) => Some(notice),
    }
}

pub fn reset(data_dir: &Path, vault_id: &str, revision: u64) -> VaultResult<()> {
    write_record(
        data_dir,
        &HighWater {
            vault_id: vault_id.to_string(),
            revision,
        },
    )
}

#[derive(Default)]
pub struct RollbackGuard {
    notice: Mutex<Option<RollbackNotice>>,
}

impl RollbackGuard {
    fn set(&self, notice: Option<RollbackNotice>) {
        if let Ok(mut current) = self.notice.lock() {
            *current = notice;
        }
    }

    fn current(&self) -> Option<RollbackNotice> {
        self.notice.lock().ok().and_then(|notice| notice.clone())
    }
}

fn data_dir(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_local_data_dir().ok()
}

pub fn observe_unlock(app: &AppHandle, snapshot: &VaultSnapshot) {
    let Some(guard) = app.try_state::<RollbackGuard>() else {
        return;
    };
    let notice = match (data_dir(app), snapshot.vault_id.as_deref()) {
        (Some(dir), Some(vault_id)) => observe(&dir, vault_id, snapshot.revision),
        _ => None,
    };
    guard.set(notice);
}

pub fn observe_lock(app: &AppHandle, state: &VaultState) {
    let snapshot = state
        .session
        .lock()
        .ok()
        .and_then(|session| session.as_ref().map(|unlocked| unlocked.snapshot()));
    if let (Some(snapshot), Some(dir)) = (snapshot, data_dir(app)) {
        if let Some(vault_id) = snapshot.vault_id.as_deref() {
            let _ = observe(&dir, vault_id, snapshot.revision);
        }
    }
    if let Some(guard) = app.try_state::<RollbackGuard>() {
        guard.set(None);
    }
}

pub fn reset_after_restore(app: &AppHandle, vault_id: Option<&str>, revision: u64) {
    if let (Some(dir), Some(vault_id)) = (data_dir(app), vault_id) {
        let _ = reset(&dir, vault_id, revision);
    }
    if let Some(guard) = app.try_state::<RollbackGuard>() {
        guard.set(None);
    }
}

#[tauri::command]
pub fn get_rollback_notice(guard: State<'_, RollbackGuard>) -> Option<RollbackNotice> {
    guard.current()
}

#[tauri::command]
pub fn accept_rollback(
    app: AppHandle,
    guard: State<'_, RollbackGuard>,
    state: State<'_, VaultState>,
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
    let dir = data_dir(&app).ok_or("Sesame could not find its data folder.")?;
    reset(&dir, &vault_id, snapshot.revision)?;
    guard.set(None);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sesame-rollback-guard-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mark(id: &str, revision: u64) -> HighWater {
        HighWater {
            vault_id: id.to_string(),
            revision,
        }
    }

    #[test]
    fn a_first_open_and_a_higher_revision_raise_the_record() {
        assert_eq!(
            judge(None, "vault-a", 4),
            Verdict::Raise(mark("vault-a", 4))
        );
        assert_eq!(
            judge(Some(&mark("vault-a", 4)), "vault-a", 9),
            Verdict::Raise(mark("vault-a", 9))
        );
    }

    #[test]
    fn the_same_revision_changes_nothing() {
        assert_eq!(
            judge(Some(&mark("vault-a", 4)), "vault-a", 4),
            Verdict::Unchanged
        );
    }

    #[test]
    fn a_lower_revision_of_the_same_vault_is_named_with_both_numbers() {
        assert_eq!(
            judge(Some(&mark("vault-a", 9)), "vault-a", 4),
            Verdict::Below(RollbackNotice {
                recorded_revision: 9,
                found_revision: 4
            })
        );
    }

    #[test]
    fn another_vault_is_never_compared_with_the_record() {
        assert_eq!(
            judge(Some(&mark("vault-a", 9)), "vault-b", 1),
            Verdict::Raise(mark("vault-b", 1))
        );
    }

    #[test]
    fn observing_writes_the_record_and_flags_a_rollback_without_lowering_it() {
        let dir = scratch("observe");
        assert_eq!(observe(&dir, "vault-a", 5), None);
        assert_eq!(read_record(&dir), Some(mark("vault-a", 5)));
        assert_eq!(observe(&dir, "vault-a", 8), None);
        assert_eq!(read_record(&dir), Some(mark("vault-a", 8)));

        let notice = observe(&dir, "vault-a", 3).expect("rollback");
        assert_eq!(notice.recorded_revision, 8);
        assert_eq!(notice.found_revision, 3);
        assert_eq!(read_record(&dir), Some(mark("vault-a", 8)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_confirmed_reset_lowers_the_record_so_the_next_open_is_quiet() {
        let dir = scratch("reset");
        observe(&dir, "vault-a", 8);
        reset(&dir, "vault-a", 3).unwrap();
        assert_eq!(observe(&dir, "vault-a", 3), None);
        assert_eq!(read_record(&dir), Some(mark("vault-a", 3)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restoring_an_older_backup_needs_a_confirmation_that_names_both_revisions() {
        assert_eq!(
            require_older_confirmation(3, Some(8), false),
            Err("olderBackup:3:8".to_string())
        );
        assert_eq!(require_older_confirmation(3, Some(8), true), Ok(()));
    }

    #[test]
    fn a_same_or_newer_backup_and_a_restore_with_no_active_vault_need_none() {
        assert_eq!(require_older_confirmation(8, Some(8), false), Ok(()));
        assert_eq!(require_older_confirmation(9, Some(8), false), Ok(()));
        assert_eq!(require_older_confirmation(1, None, false), Ok(()));
    }

    #[test]
    fn an_edited_or_damaged_record_is_not_trusted() {
        let dir = scratch("edited");
        observe(&dir, "vault-a", 8);
        let path = record_path(&dir);
        let body = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, body.replace('8', "1")).unwrap();
        assert_eq!(read_record(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
