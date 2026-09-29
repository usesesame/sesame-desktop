use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::vault::VaultResult;

pub const DESKTOP_SETTINGS_FILE: &str = "desktop-settings.json";
const MAX_SETTINGS_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct DesktopSettings {
    pub website_icons_enabled: bool,
}

pub fn settings_path(app: &AppHandle) -> VaultResult<PathBuf> {
    let mut path = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
    path.push(DESKTOP_SETTINGS_FILE);
    Ok(path)
}

pub fn read_settings_at(path: &Path) -> Option<DesktopSettings> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() > MAX_SETTINGS_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn write_settings_at(path: &Path, settings: &DesktopSettings) -> VaultResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|_| "Sesame could not prepare its local data folder.".to_string())?;
    }
    let bytes = serde_json::to_vec(settings)
        .map_err(|_| "Sesame could not save the desktop setting.".to_string())?;
    crate::vault::storage::atomic_replace(path, &bytes)
}

pub fn website_icons_enabled_at(path: &Path) -> bool {
    read_settings_at(path).is_some_and(|settings| settings.website_icons_enabled)
}

pub fn require_website_icons_enabled(path: &Path) -> VaultResult<()> {
    if website_icons_enabled_at(path) {
        Ok(())
    } else {
        Err("Website icons are turned off in Sesame settings.".to_string())
    }
}

#[tauri::command]
pub fn get_website_icons_enabled(app: AppHandle) -> VaultResult<Option<bool>> {
    Ok(read_settings_at(&settings_path(&app)?).map(|settings| settings.website_icons_enabled))
}

#[tauri::command]
pub fn set_website_icons_enabled(app: AppHandle, enabled: bool) -> VaultResult<()> {
    let path = settings_path(&app)?;
    let mut settings = read_settings_at(&path).unwrap_or_default();
    settings.website_icons_enabled = enabled;
    write_settings_at(&path, &settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sesame-desktop-settings-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("test directory");
        dir.join(DESKTOP_SETTINGS_FILE)
    }

    #[test]
    fn a_missing_settings_file_keeps_website_icons_off() {
        let path = test_path("missing");
        assert!(!website_icons_enabled_at(&path));
        assert!(require_website_icons_enabled(&path).is_err());
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }

    #[test]
    fn the_website_icon_preference_survives_a_round_trip() {
        let path = test_path("round-trip");
        write_settings_at(
            &path,
            &DesktopSettings {
                website_icons_enabled: true,
            },
        )
        .expect("enable setting");
        assert!(website_icons_enabled_at(&path));
        assert!(require_website_icons_enabled(&path).is_ok());
        write_settings_at(
            &path,
            &DesktopSettings {
                website_icons_enabled: false,
            },
        )
        .expect("disable setting");
        assert!(!website_icons_enabled_at(&path));
        assert!(require_website_icons_enabled(&path).is_err());
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }

    #[test]
    fn unreadable_settings_do_not_enable_website_icons() {
        let path = test_path("unreadable");
        fs::write(&path, b"not a settings file").expect("write settings");
        assert!(!website_icons_enabled_at(&path));
        assert!(require_website_icons_enabled(&path).is_err());
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }

    #[test]
    fn an_oversized_settings_file_does_not_enable_website_icons() {
        let path = test_path("oversized");
        fs::write(&path, vec![b' '; (MAX_SETTINGS_BYTES + 1) as usize]).expect("write settings");
        assert!(!website_icons_enabled_at(&path));
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }
}
