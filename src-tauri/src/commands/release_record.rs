use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::application::browser_fill_broker::BrowserFillState;
use crate::application::release_record::{
    clear_release_record_in_state, release_record_hint_in_state, release_record_page_in_state,
    release_record_status_in_state, set_release_record_retention_in_state, ReleaseRecordHint,
    ReleaseRecordPage, ReleaseRecordQuery, ReleaseRecordStatus,
};
use crate::release::ReleasePresence;
use crate::vault::release_record::DEFAULT_RETENTION_DAYS;
use crate::vault::util::unix_timestamp;
use crate::vault::{VaultResult, VaultState};

pub(crate) const RELEASE_RECORD_CHANGED: &str = "release-record-changed";
const RECORD_SETTINGS_FILE: &str = "activity-settings.json";
const MAX_RECORD_SETTINGS_BYTES: u64 = 4 * 1024;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct RecordSettings {
    pub retention_days: Option<u32>,
}

fn record_settings_path(app: &AppHandle) -> VaultResult<PathBuf> {
    let mut path = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
    path.push(RECORD_SETTINGS_FILE);
    Ok(path)
}

pub(crate) fn read_record_settings_at(path: &Path) -> RecordSettings {
    crate::vault::util::read_file_with_limit(path, MAX_RECORD_SETTINGS_BYTES)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_record_settings_at(path: &Path, settings: &RecordSettings) -> VaultResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| "Sesame could not prepare its local data folder.".to_string())?;
    }
    let bytes = serde_json::to_vec(settings)
        .map_err(|_| "Sesame could not save the activity setting.".to_string())?;
    crate::vault::storage::atomic_replace(path, &bytes)
}

pub(crate) fn load_release_record_settings(app: &AppHandle) {
    let days = record_settings_path(app)
        .map(|path| read_record_settings_at(&path))
        .ok()
        .and_then(|settings| settings.retention_days)
        .unwrap_or(DEFAULT_RETENTION_DAYS);
    app.state::<VaultState>()
        .release_record
        .set_retention_days(days);
}

pub(crate) fn announce_release_record(app: &AppHandle) {
    let status = release_record_status_in_state(&app.state::<VaultState>());
    let _ = app.emit_to("main", RELEASE_RECORD_CHANGED, status);
}

#[tauri::command]
pub fn get_release_record(
    query: Option<ReleaseRecordQuery>,
    state: State<'_, VaultState>,
) -> VaultResult<ReleaseRecordPage> {
    release_record_page_in_state(&state, query.unwrap_or_default())
}

#[tauri::command]
pub fn get_release_record_status(state: State<'_, VaultState>) -> ReleaseRecordStatus {
    release_record_status_in_state(&state)
}

#[tauri::command]
pub fn get_release_record_hint(
    approval_id: String,
    state: State<'_, VaultState>,
    fill_state: State<'_, BrowserFillState>,
) -> VaultResult<Option<ReleaseRecordHint>> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Ok(None);
    }
    release_record_hint_in_state(&state, &fill_state, &approval_id, unix_timestamp())
}

#[tauri::command]
pub fn set_release_record_retention(
    app: AppHandle,
    days: u32,
    state: State<'_, VaultState>,
) -> VaultResult<ReleaseRecordStatus> {
    let status = set_release_record_retention_in_state(&state, days)?;
    write_record_settings_at(
        &record_settings_path(&app)?,
        &RecordSettings {
            retention_days: Some(status.retention_days),
        },
    )?;
    announce_release_record(&app);
    Ok(status)
}

#[tauri::command]
pub fn clear_release_record(
    app: AppHandle,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<ReleaseRecordStatus> {
    let status = clear_release_record_in_state(&state, &presence)?;
    announce_release_record(&app);
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_activity_setting_round_trips_and_ignores_bad_files() {
        let directory = std::env::temp_dir().join(format!(
            "sesame-activity-settings-{}",
            crate::vault::random_id()
        ));
        let path = directory.join(RECORD_SETTINGS_FILE);
        assert_eq!(read_record_settings_at(&path), RecordSettings::default());
        write_record_settings_at(
            &path,
            &RecordSettings {
                retention_days: Some(90),
            },
        )
        .expect("written");
        assert_eq!(read_record_settings_at(&path).retention_days, Some(90));
        std::fs::write(&path, b"not json").expect("garbage");
        assert_eq!(read_record_settings_at(&path), RecordSettings::default());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
