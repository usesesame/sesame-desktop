use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::vault::{fill_random, VaultResult};

const FILE_CHOICE_TTL: Duration = Duration::from_secs(120);

const CHOICE_LOCK_ERROR: &str = "Sesame could not read the file choice.";
const STALE_CHOICE: &str = "That file choice expired or was already used. Choose the file again.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FilePurpose {
    ImportSource,
    BackupExport,
    CsvExport,
    RecoveryKitExport,
    DiagnosticsExport,
    BackupRead,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ChosenFile {
    pub token: String,
    pub file_name: String,
}

#[derive(Default)]
pub struct FileSelectionState {
    choices: Mutex<HashMap<String, PendingChoice>>,
}

struct PendingChoice {
    purpose: FilePurpose,
    path: PathBuf,
    expires_at: Instant,
    claimed: bool,
}

pub(crate) struct FileClaim {
    token: String,
    path: PathBuf,
}

impl FileClaim {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl FileSelectionState {
    fn issue(&self, purpose: FilePurpose, path: PathBuf) -> VaultResult<String> {
        let mut bytes = [0_u8; 32];
        fill_random(&mut bytes);
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let mut choices = self
            .choices
            .lock()
            .map_err(|_| CHOICE_LOCK_ERROR.to_string())?;
        let now = Instant::now();
        choices.retain(|_, choice| choice.claimed || choice.expires_at > now);
        choices.insert(
            token.clone(),
            PendingChoice {
                purpose,
                path,
                expires_at: now + FILE_CHOICE_TTL,
                claimed: false,
            },
        );
        Ok(token)
    }

    pub(crate) fn claim(&self, token: &str, purpose: FilePurpose) -> VaultResult<FileClaim> {
        let mut choices = self
            .choices
            .lock()
            .map_err(|_| CHOICE_LOCK_ERROR.to_string())?;
        let now = Instant::now();
        choices.retain(|_, choice| choice.claimed || choice.expires_at > now);
        let choice = choices
            .get_mut(token)
            .ok_or_else(|| STALE_CHOICE.to_string())?;
        if choice.purpose != purpose || choice.claimed || choice.expires_at <= now {
            return Err(STALE_CHOICE.into());
        }
        choice.claimed = true;
        Ok(FileClaim {
            token: token.to_string(),
            path: choice.path.clone(),
        })
    }

    pub(crate) fn release(&self, claim: FileClaim) {
        if let Ok(mut choices) = self.choices.lock() {
            if let Some(choice) = choices.get_mut(&claim.token) {
                choice.claimed = false;
                choice.expires_at = Instant::now() + FILE_CHOICE_TTL;
            }
        }
    }

    pub(crate) fn consume(&self, claim: FileClaim) {
        if let Ok(mut choices) = self.choices.lock() {
            choices.remove(&claim.token);
        }
    }

    pub(crate) fn take(&self, token: &str, purpose: FilePurpose) -> VaultResult<PathBuf> {
        let mut choices = self
            .choices
            .lock()
            .map_err(|_| CHOICE_LOCK_ERROR.to_string())?;
        let now = Instant::now();
        choices.retain(|_, choice| choice.claimed || choice.expires_at > now);
        let choice = choices.get(token).ok_or_else(|| STALE_CHOICE.to_string())?;
        if choice.purpose != purpose || choice.claimed || choice.expires_at <= now {
            return Err(STALE_CHOICE.into());
        }
        choices
            .remove(token)
            .map(|choice| choice.path)
            .ok_or_else(|| STALE_CHOICE.to_string())
    }

    pub(crate) fn peek(&self, token: &str, purpose: FilePurpose) -> VaultResult<PathBuf> {
        let mut choices = self
            .choices
            .lock()
            .map_err(|_| CHOICE_LOCK_ERROR.to_string())?;
        let now = Instant::now();
        choices.retain(|_, choice| choice.claimed || choice.expires_at > now);
        let choice = choices.get(token).ok_or_else(|| STALE_CHOICE.to_string())?;
        if choice.purpose != purpose || choice.claimed {
            return Err(STALE_CHOICE.into());
        }
        Ok(choice.path.clone())
    }
}

fn chosen_file(
    state: &FileSelectionState,
    purpose: FilePurpose,
    path: Option<PathBuf>,
) -> VaultResult<Option<ChosenFile>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| "Sesame could not read the chosen file name.".to_string())?;
    let token = state.issue(purpose, path)?;
    Ok(Some(ChosenFile { token, file_name }))
}

pub(crate) fn resolve_path(
    state: &FileSelectionState,
    token: Option<&str>,
    path: Option<&str>,
    purpose: FilePurpose,
    spend: bool,
) -> VaultResult<PathBuf> {
    if let Some(token) = token.filter(|token| !token.is_empty()) {
        return if spend {
            state.take(token, purpose)
        } else {
            state.peek(token, purpose)
        };
    }
    #[cfg(feature = "wdio")]
    if let Some(path) = path.filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    #[cfg(not(feature = "wdio"))]
    let _ = path;
    Err(STALE_CHOICE.into())
}

fn path_from_file(file: tauri_plugin_dialog::FilePath) -> Option<PathBuf> {
    file.into_path().ok()
}

fn dated_name(prefix: &str, extension: &str) -> String {
    format!(
        "{prefix}-{}.{extension}",
        chrono::Utc::now().format("%Y-%m-%d")
    )
}

#[tauri::command]
pub async fn choose_import_file(
    app: AppHandle,
    source: String,
    state: State<'_, FileSelectionState>,
) -> VaultResult<Option<ChosenFile>> {
    let builder = app.dialog().file().set_title("Choose a file to import");
    let builder = match source.as_str() {
        "otpauth-txt" => builder.add_filter("Authenticator export", &["txt"]),
        "bitwarden-json" | "aegis-json" | "2fas-json" => {
            builder.add_filter("JSON export", &["json"])
        }
        _ => builder.add_filter("CSV export", &["csv"]),
    };
    chosen_file(
        &state,
        FilePurpose::ImportSource,
        builder.blocking_pick_file().and_then(path_from_file),
    )
}

#[tauri::command]
pub async fn choose_backup_export_destination(
    app: AppHandle,
    state: State<'_, FileSelectionState>,
) -> VaultResult<Option<ChosenFile>> {
    chosen_file(
        &state,
        FilePurpose::BackupExport,
        app.dialog()
            .file()
            .set_title("Save the encrypted backup")
            .set_file_name(dated_name("sesame-backup", "sesame"))
            .add_filter("Sesame encrypted backup", &["sesame"])
            .blocking_save_file()
            .and_then(path_from_file),
    )
}

#[tauri::command]
pub async fn choose_csv_export_destination(
    app: AppHandle,
    state: State<'_, FileSelectionState>,
) -> VaultResult<Option<ChosenFile>> {
    chosen_file(
        &state,
        FilePurpose::CsvExport,
        app.dialog()
            .file()
            .set_title("Save the readable export")
            .set_file_name(dated_name("sesame-vault-export", "csv"))
            .add_filter("Sesame readable export", &["csv"])
            .blocking_save_file()
            .and_then(path_from_file),
    )
}

#[tauri::command]
pub async fn choose_recovery_kit_destination(
    app: AppHandle,
    state: State<'_, FileSelectionState>,
) -> VaultResult<Option<ChosenFile>> {
    chosen_file(
        &state,
        FilePurpose::RecoveryKitExport,
        app.dialog()
            .file()
            .set_title("Save the recovery kit")
            .set_file_name(dated_name("sesame-recovery-kit", "txt"))
            .add_filter("Text file", &["txt"])
            .blocking_save_file()
            .and_then(path_from_file),
    )
}

#[tauri::command]
pub async fn choose_diagnostics_destination(
    app: AppHandle,
    state: State<'_, FileSelectionState>,
) -> VaultResult<Option<ChosenFile>> {
    chosen_file(
        &state,
        FilePurpose::DiagnosticsExport,
        app.dialog()
            .file()
            .set_title("Save the diagnostic log")
            .set_file_name(dated_name("sesame-diagnostics", "jsonl"))
            .add_filter("Sesame diagnostic log", &["jsonl"])
            .blocking_save_file()
            .and_then(path_from_file),
    )
}

#[tauri::command]
pub async fn choose_backup_for_restore(
    app: AppHandle,
    state: State<'_, FileSelectionState>,
) -> VaultResult<Option<ChosenFile>> {
    chosen_file(
        &state,
        FilePurpose::BackupRead,
        app.dialog()
            .file()
            .set_title("Choose an encrypted backup")
            .add_filter("Sesame encrypted backup", &["sesame"])
            .blocking_pick_file()
            .and_then(path_from_file),
    )
}

#[cfg(feature = "wdio")]
#[tauri::command]
pub fn wdio_issue_file_choice(
    path: String,
    state: State<'_, FileSelectionState>,
) -> VaultResult<ChosenFile> {
    chosen_file(&state, FilePurpose::BackupRead, Some(PathBuf::from(path)))?
        .ok_or_else(|| STALE_CHOICE.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with(purpose: FilePurpose, path: &str) -> (FileSelectionState, String) {
        let state = FileSelectionState::default();
        let token = state
            .issue(purpose, PathBuf::from(path))
            .expect("issued token");
        (state, token)
    }

    #[test]
    fn a_file_token_resolves_once_and_then_fails() {
        let (state, token) = state_with(FilePurpose::ImportSource, "fictional-export.csv");
        let resolved = resolve_path(&state, Some(&token), None, FilePurpose::ImportSource, true)
            .expect("first resolve");
        assert_eq!(resolved, PathBuf::from("fictional-export.csv"));
        assert_eq!(
            resolve_path(&state, Some(&token), None, FilePurpose::ImportSource, true),
            Err(STALE_CHOICE.to_string())
        );
    }

    #[test]
    fn a_file_token_is_bound_to_its_purpose() {
        let (state, token) = state_with(FilePurpose::BackupExport, "fictional-backup.sesame");
        assert_eq!(
            resolve_path(&state, Some(&token), None, FilePurpose::ImportSource, true),
            Err(STALE_CHOICE.to_string())
        );
        assert_eq!(
            resolve_path(&state, Some(&token), None, FilePurpose::BackupExport, true),
            Ok(PathBuf::from("fictional-backup.sesame"))
        );
    }

    #[test]
    fn a_read_keeps_the_token_until_the_restore_spends_it() {
        let (state, token) = state_with(FilePurpose::BackupRead, "fictional-backup.sesame");
        assert!(resolve_path(&state, Some(&token), None, FilePurpose::BackupRead, false).is_ok());
        assert!(resolve_path(&state, Some(&token), None, FilePurpose::BackupRead, false).is_ok());
        assert!(resolve_path(&state, Some(&token), None, FilePurpose::BackupRead, true).is_ok());
        assert_eq!(
            resolve_path(&state, Some(&token), None, FilePurpose::BackupRead, false),
            Err(STALE_CHOICE.to_string())
        );
    }

    #[test]
    fn an_expired_file_token_is_refused() {
        let (state, token) = state_with(FilePurpose::DiagnosticsExport, "fictional-log.jsonl");
        state
            .choices
            .lock()
            .expect("choice lock")
            .get_mut(&token)
            .expect("pending choice")
            .expires_at = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            resolve_path(
                &state,
                Some(&token),
                None,
                FilePurpose::DiagnosticsExport,
                true
            ),
            Err(STALE_CHOICE.to_string())
        );
    }

    #[test]
    fn an_expired_token_is_refused_before_it_is_claimed() {
        let (state, token) = state_with(FilePurpose::BackupRead, "fictional-backup.sesame");
        state
            .choices
            .lock()
            .expect("choice lock")
            .get_mut(&token)
            .expect("pending choice")
            .expires_at = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            state.claim(&token, FilePurpose::BackupRead).err(),
            Some(STALE_CHOICE.to_string())
        );
    }

    #[test]
    fn a_failed_restore_releases_the_token_for_a_retry() {
        let (state, token) = state_with(FilePurpose::BackupRead, "fictional-backup.sesame");
        let claim = state
            .claim(&token, FilePurpose::BackupRead)
            .expect("first claim");
        state
            .choices
            .lock()
            .expect("choice lock")
            .get_mut(&token)
            .expect("pending choice")
            .expires_at = Instant::now() - Duration::from_secs(1);
        state.release(claim);
        let retry = state
            .claim(&token, FilePurpose::BackupRead)
            .expect("retry claim");
        assert_eq!(retry.path(), Path::new("fictional-backup.sesame"));
    }

    #[test]
    fn a_claimed_token_is_not_available_to_another_caller() {
        let (state, token) = state_with(FilePurpose::BackupRead, "fictional-backup.sesame");
        let _claim = state
            .claim(&token, FilePurpose::BackupRead)
            .expect("first claim");
        assert_eq!(
            state.claim(&token, FilePurpose::BackupRead).err(),
            Some(STALE_CHOICE.to_string())
        );
        assert_eq!(
            resolve_path(&state, Some(&token), None, FilePurpose::BackupRead, true),
            Err(STALE_CHOICE.to_string())
        );
        assert_eq!(
            resolve_path(&state, Some(&token), None, FilePurpose::BackupRead, false),
            Err(STALE_CHOICE.to_string())
        );
    }

    #[test]
    fn an_in_flight_claim_outlasts_the_choice_expiry() {
        let (state, token) = state_with(FilePurpose::BackupRead, "fictional-backup.sesame");
        let claim = state
            .claim(&token, FilePurpose::BackupRead)
            .expect("first claim");
        state
            .choices
            .lock()
            .expect("choice lock")
            .get_mut(&token)
            .expect("pending choice")
            .expires_at = Instant::now() - Duration::from_secs(1);
        state.consume(claim);
        assert_eq!(
            state.claim(&token, FilePurpose::BackupRead).err(),
            Some(STALE_CHOICE.to_string())
        );
    }

    #[test]
    fn a_successful_restore_spends_the_token() {
        let (state, token) = state_with(FilePurpose::BackupRead, "fictional-backup.sesame");
        let claim = state
            .claim(&token, FilePurpose::BackupRead)
            .expect("first claim");
        state.consume(claim);
        assert_eq!(
            state.claim(&token, FilePurpose::BackupRead).err(),
            Some(STALE_CHOICE.to_string())
        );
        assert_eq!(
            resolve_path(&state, Some(&token), None, FilePurpose::BackupRead, false),
            Err(STALE_CHOICE.to_string())
        );
    }

    #[test]
    fn a_file_claim_is_bound_to_its_purpose() {
        let (state, token) = state_with(FilePurpose::BackupRead, "fictional-backup.sesame");
        assert_eq!(
            state.claim(&token, FilePurpose::BackupExport).err(),
            Some(STALE_CHOICE.to_string())
        );
        let claim = state
            .claim(&token, FilePurpose::BackupRead)
            .expect("right purpose");
        state.release(claim);
    }

    #[test]
    fn a_cancelled_dialog_registers_no_choice() {
        let state = FileSelectionState::default();
        assert!(chosen_file(&state, FilePurpose::BackupExport, None)
            .expect("no choice")
            .is_none());
    }

    #[test]
    fn a_registered_choice_carries_its_file_name_to_the_renderer() {
        let state = FileSelectionState::default();
        let chosen = chosen_file(
            &state,
            FilePurpose::RecoveryKitExport,
            Some(PathBuf::from(
                "/fictional/place/sesame-recovery-kit-2026-09-29.txt",
            )),
        )
        .expect("registered")
        .expect("choice");
        assert_eq!(chosen.file_name, "sesame-recovery-kit-2026-09-29.txt");
        assert!(!chosen.token.is_empty());
    }

    #[cfg(not(feature = "wdio"))]
    #[test]
    fn a_raw_path_without_a_token_is_refused() {
        let state = FileSelectionState::default();
        assert_eq!(
            resolve_path(
                &state,
                None,
                Some("fictional-backup.sesame"),
                FilePurpose::BackupRead,
                false
            ),
            Err(STALE_CHOICE.to_string())
        );
    }

    #[cfg(feature = "wdio")]
    #[test]
    fn the_wdio_bridge_may_pass_a_raw_path() {
        let state = FileSelectionState::default();
        assert_eq!(
            resolve_path(
                &state,
                None,
                Some("/fictional/place/backup.sesame"),
                FilePurpose::BackupRead,
                false
            ),
            Ok(PathBuf::from("/fictional/place/backup.sesame"))
        );
    }
}
