use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::adapters::network::trusted_time::trusted_time;
use crate::commands::{require_release_presence, retire_unlock_methods_after_key_rotation};
use crate::release::ReleasePresence;
use crate::vault::backup::RECOVERY_REPLACEMENT_FILE;
use crate::vault::storage::{
    atomic_replace, open_recovery_replacement_request, recovery_replacement_ready,
    replace_recovery_kit_for_session, seal_recovery_replacement_request, vault_path,
    VaultKeyRotation, RECOVERY_REPLACEMENT_DELAY_SECS,
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

fn request_path(app: &AppHandle) -> VaultResult<PathBuf> {
    let vault = vault_path(app)?;
    let parent = vault
        .parent()
        .ok_or("Sesame could not locate the vault folder.")?;
    Ok(parent.join(RECOVERY_REPLACEMENT_FILE))
}

fn remove_request(path: &Path) -> VaultResult<()> {
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

fn pending_request(path: &Path, session: &UnlockedVault) -> VaultResult<Option<u64>> {
    Ok(read_request(path, session)?.map(|(_, requested_at)| requested_at))
}

fn write_request(path: &Path, session: &UnlockedVault, requested_at: u64) -> VaultResult<()> {
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

fn complete_request(
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

fn pending_for_unlocked(app: &AppHandle, state: &VaultState) -> VaultResult<Option<u64>> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    pending_request(&request_path(app)?, session)
}

async fn status_for(requested_at: Option<u64>) -> RecoveryReplacementStatus {
    let Some(requested_at) = requested_at else {
        return RecoveryReplacementStatus::default();
    };
    let confirmed = trusted_time().await.ok();
    RecoveryReplacementStatus {
        requested_at: Some(requested_at),
        available_at: Some(requested_at.saturating_add(RECOVERY_REPLACEMENT_DELAY_SECS)),
        ready: confirmed
            .is_some_and(|time| recovery_replacement_ready(requested_at, time.earliest)),
        time_confirmed: confirmed.is_some(),
    }
}

#[tauri::command]
pub async fn get_recovery_replacement_status(
    app: AppHandle,
    state: State<'_, VaultState>,
) -> VaultResult<RecoveryReplacementStatus> {
    let pending = pending_for_unlocked(&app, &state)?;
    Ok(status_for(pending).await)
}

#[tauri::command]
pub async fn request_recovery_replacement(
    app: AppHandle,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<RecoveryReplacementStatus> {
    require_release_presence(&state, &presence)?;
    if let Some(requested_at) = pending_for_unlocked(&app, &state)? {
        return Ok(status_for(Some(requested_at)).await);
    }
    let requested_at = trusted_time().await?.latest;
    {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the vault session.".to_string())?;
        let session = session.as_ref().ok_or("Unlock your vault first.")?;
        write_request(&request_path(&app)?, session, requested_at)?;
    }
    Ok(status_for(Some(requested_at)).await)
}

#[tauri::command]
pub fn cancel_recovery_replacement(
    app: AppHandle,
    state: State<'_, VaultState>,
) -> VaultResult<()> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    session.as_ref().ok_or("Unlock your vault first.")?;
    remove_request(&request_path(&app)?)
}

#[tauri::command]
pub async fn complete_recovery_replacement(
    app: AppHandle,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
    master_password: String,
    prune_backups: bool,
) -> VaultResult<RecoveryReplacementResult> {
    let master_password = Zeroizing::new(master_password);
    require_release_presence(&state, &presence)?;
    pending_for_unlocked(&app, &state)?.ok_or("There is no recovery kit request to complete.")?;
    let now = trusted_time().await?.earliest;
    let rotation = {
        let epoch = state.session_epoch();
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the vault session.".to_string())?;
        let session = session.as_mut().ok_or("Unlock your vault first.")?;
        presence.grant_with_password(session, epoch, &master_password)?;
        complete_request(
            &request_path(&app)?,
            session,
            &master_password,
            now,
            prune_backups,
        )?
    };
    retire_unlock_methods_after_key_rotation(&app, &state);
    Ok(RecoveryReplacementResult {
        recovery_kit: rotation.recovery_kit,
        backups_remaining: rotation.backups_remaining,
    })
}

pub(crate) fn discard_recovery_replacement(app: &AppHandle) {
    if let Ok(path) = request_path(app) {
        let _ = remove_request(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::random_id;
    use crate::vault::storage::persist_session;
    use crate::vault::types::VaultFile;
    use sesame_core::api::{create_vault, open_vault_with_recovery_kit};

    const PASSWORD: &str = "fictional master password";
    const REQUESTED_AT: u64 = 1_800_000_000;
    const READY_AT: u64 = REQUESTED_AT + RECOVERY_REPLACEMENT_DELAY_SECS;

    struct Fixture {
        directory: PathBuf,
        request: PathBuf,
        session: UnlockedVault,
        kit: String,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn requested() -> Fixture {
        let directory =
            std::env::temp_dir().join(format!("sesame-recovery-request-{}", random_id()));
        std::fs::create_dir_all(directory.join("request")).expect("test directory");
        let (opened, kit) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
        let mut session = UnlockedVault::from_opened(directory.join("vault.sesame"), &opened)
            .expect("unlocked vault");
        session.setup_complete = true;
        persist_session(&mut session).expect("persisted vault");
        let request = directory.join("request").join(RECOVERY_REPLACEMENT_FILE);
        write_request(&request, &session, REQUESTED_AT).expect("written request");
        Fixture {
            directory,
            request,
            session,
            kit,
        }
    }

    fn kit_opens(fixture: &Fixture, kit: &str) -> bool {
        let bytes = std::fs::read(fixture.directory.join("vault.sesame")).expect("vault bytes");
        let file: VaultFile = serde_json::from_slice(&bytes).expect("vault file");
        open_vault_with_recovery_kit(&file, kit).is_ok()
    }

    #[test]
    fn a_completed_request_cannot_be_completed_again() {
        let mut fixture = requested();
        let kit = complete_request(
            &fixture.request,
            &mut fixture.session,
            PASSWORD,
            READY_AT,
            false,
        )
        .expect("replaced kit")
        .recovery_kit;
        assert!(!fixture.request.exists());
        assert!(complete_request(
            &fixture.request,
            &mut fixture.session,
            PASSWORD,
            READY_AT + 60,
            false
        )
        .is_err());
        assert!(kit_opens(&fixture, &kit));
        assert!(!kit_opens(&fixture, &fixture.kit));
    }

    #[test]
    fn a_wrong_master_password_keeps_the_request_and_the_current_kit() {
        let mut fixture = requested();
        let before = std::fs::read(fixture.directory.join("vault.sesame")).expect("vault bytes");

        let error = complete_request(
            &fixture.request,
            &mut fixture.session,
            "fictional wrong password",
            READY_AT,
            false,
        )
        .err()
        .expect("refused");

        assert!(error.contains("master password is not correct"), "{error}");
        assert_eq!(
            std::fs::read(fixture.directory.join("vault.sesame")).expect("vault bytes"),
            before
        );
        assert!(kit_opens(&fixture, &fixture.kit));
        assert_eq!(
            pending_request(&fixture.request, &fixture.session),
            Ok(Some(REQUESTED_AT))
        );
        assert!(complete_request(
            &fixture.request,
            &mut fixture.session,
            PASSWORD,
            READY_AT,
            false
        )
        .is_ok());
    }

    #[test]
    fn a_completed_request_prunes_local_backups_only_when_asked() {
        let mut fixture = requested();
        let backups = fixture.directory.join("backups");
        std::fs::create_dir_all(&backups).expect("backup folder");
        let old_copy = std::fs::read(fixture.directory.join("vault.sesame")).expect("vault bytes");
        std::fs::write(backups.join("sesame-backup-fictional.sesame"), &old_copy).expect("backup");

        let kept = complete_request(
            &fixture.request,
            &mut fixture.session,
            PASSWORD,
            READY_AT,
            false,
        )
        .expect("replaced kit");
        assert_eq!(kept.backups_remaining, None);
        assert!(backups.join("sesame-backup-fictional.sesame").exists());

        write_request(&fixture.request, &fixture.session, REQUESTED_AT).expect("second request");
        let pruned = complete_request(
            &fixture.request,
            &mut fixture.session,
            PASSWORD,
            READY_AT,
            true,
        )
        .expect("replaced kit again");
        assert_eq!(pruned.backups_remaining, Some(0));
        assert!(!backups.join("sesame-backup-fictional.sesame").exists());
    }

    #[test]
    fn an_early_completion_keeps_the_request() {
        let mut fixture = requested();
        assert!(complete_request(
            &fixture.request,
            &mut fixture.session,
            PASSWORD,
            READY_AT - 1,
            false
        )
        .is_err());
        assert_eq!(
            pending_request(&fixture.request, &fixture.session),
            Ok(Some(REQUESTED_AT))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_request_that_cannot_be_removed_replaces_nothing() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = requested();
        let request_directory = fixture.directory.join("request");
        let readable = std::fs::metadata(&request_directory)
            .expect("directory metadata")
            .permissions();
        std::fs::set_permissions(&request_directory, std::fs::Permissions::from_mode(0o500))
            .expect("read-only directory");
        let result = complete_request(
            &fixture.request,
            &mut fixture.session,
            PASSWORD,
            READY_AT,
            false,
        );
        std::fs::set_permissions(&request_directory, readable).expect("restored directory");
        assert!(result.is_err());
        assert!(kit_opens(&fixture, &fixture.kit));
        assert_eq!(
            pending_request(&fixture.request, &fixture.session),
            Ok(Some(REQUESTED_AT))
        );
    }

    #[test]
    fn no_request_serializes_without_a_request_time() {
        let json = serde_json::to_value(RecoveryReplacementStatus::default()).expect("status json");
        assert_eq!(
            json,
            serde_json::json!({ "ready": false, "timeConfirmed": false })
        );
    }
}
