use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::application::file_choices::FilePurpose;
pub use crate::application::file_choices::FileSelectionState;
#[cfg(feature = "wdio")]
use crate::application::file_choices::STALE_CHOICE;
use crate::vault::VaultResult;

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ChosenFile {
    pub token: String,
    pub file_name: String,
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

pub(crate) fn path_from_file(file: tauri_plugin_dialog::FilePath) -> Option<PathBuf> {
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
pub async fn choose_json_export_destination(
    app: AppHandle,
    state: State<'_, FileSelectionState>,
) -> VaultResult<Option<ChosenFile>> {
    chosen_file(
        &state,
        FilePurpose::JsonExport,
        app.dialog()
            .file()
            .set_title("Save the complete export")
            .set_file_name(dated_name("sesame-vault-export", "json"))
            .add_filter("Sesame complete export", &["json"])
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
}
