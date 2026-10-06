use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

use crate::release::ReleasePresence;
use crate::vault::{VaultResult, VaultState};

pub const DESKTOP_SETTINGS_FILE: &str = "desktop-settings.json";
const MAX_SETTINGS_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct DesktopSettings {
    pub website_icons_enabled: bool,
    pub screen_capture_allowed: bool,
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

pub fn screen_capture_allowed_at(path: &Path) -> bool {
    read_settings_at(path).is_some_and(|settings| settings.screen_capture_allowed)
}

pub fn set_screen_capture_allowed_at(path: &Path, allowed: bool) -> VaultResult<()> {
    let mut settings = read_settings_at(path).unwrap_or_default();
    settings.screen_capture_allowed = allowed;
    write_settings_at(path, &settings)
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
pub fn get_screen_capture_allowed(app: AppHandle) -> VaultResult<bool> {
    Ok(screen_capture_allowed_at(&settings_path(&app)?))
}

#[tauri::command]
pub fn set_screen_capture_allowed(app: AppHandle, allowed: bool) -> VaultResult<()> {
    set_screen_capture_allowed_at(&settings_path(&app)?, allowed)?;
    crate::desktop_shell::apply_capture_policy(&app);
    Ok(())
}

pub fn set_website_icons_enabled_at(
    path: &Path,
    enabled: bool,
    state: &VaultState,
    presence: &ReleasePresence,
) -> VaultResult<()> {
    if enabled {
        crate::commands::require_release_presence(state, presence)?;
    }
    let mut settings = read_settings_at(path).unwrap_or_default();
    settings.website_icons_enabled = enabled;
    write_settings_at(path, &settings)
}

#[tauri::command]
pub fn set_website_icons_enabled(
    app: AppHandle,
    enabled: bool,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<()> {
    set_website_icons_enabled_at(&settings_path(&app)?, enabled, &state, &presence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{random_id, UnlockedVault};
    use sesame_core::api::create_vault;

    fn test_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sesame-desktop-settings-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("test directory");
        dir.join(DESKTOP_SETTINGS_FILE)
    }

    fn presence_granted_state() -> (VaultState, ReleasePresence) {
        let (opened, _) =
            create_vault("fictional master password", "Fictional vault").expect("created vault");
        let path = std::env::temp_dir().join(format!("sesame-desktop-settings-{}", random_id()));
        let session = UnlockedVault::from_opened(path, &opened).expect("unlocked vault");
        let state = VaultState::default();
        let presence = ReleasePresence::default();
        presence
            .grant_with_password(&session, state.session_epoch(), "fictional master password")
            .expect("granted presence");
        (state, presence)
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
                ..DesktopSettings::default()
            },
        )
        .expect("enable setting");
        assert!(website_icons_enabled_at(&path));
        assert!(require_website_icons_enabled(&path).is_ok());
        write_settings_at(
            &path,
            &DesktopSettings {
                website_icons_enabled: false,
                ..DesktopSettings::default()
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

    #[test]
    fn enabling_website_icons_requires_presence() {
        let path = test_path("presence-enable");
        let state = VaultState::default();
        let presence = ReleasePresence::default();
        assert_eq!(
            set_website_icons_enabled_at(&path, true, &state, &presence),
            Err("presenceRequired".to_string())
        );
        assert!(!website_icons_enabled_at(&path));
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }

    #[test]
    fn disabling_website_icons_does_not_require_presence() {
        let path = test_path("presence-disable");
        write_settings_at(
            &path,
            &DesktopSettings {
                website_icons_enabled: true,
                ..DesktopSettings::default()
            },
        )
        .expect("enable setting");
        assert!(set_website_icons_enabled_at(
            &path,
            false,
            &VaultState::default(),
            &ReleasePresence::default()
        )
        .is_ok());
        assert!(!website_icons_enabled_at(&path));
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }

    #[test]
    fn screen_capture_stays_blocked_without_a_settings_file() {
        let path = test_path("capture-missing");
        assert!(!screen_capture_allowed_at(&path));
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }

    #[test]
    fn a_settings_file_from_an_earlier_release_keeps_screen_capture_blocked() {
        let path = test_path("capture-earlier-release");
        fs::write(&path, br#"{"websiteIconsEnabled":true}"#).expect("write settings");
        assert!(website_icons_enabled_at(&path));
        assert!(!screen_capture_allowed_at(&path));
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }

    #[test]
    fn the_screen_capture_choice_survives_a_round_trip_and_keeps_other_settings() {
        let path = test_path("capture-round-trip");
        write_settings_at(
            &path,
            &DesktopSettings {
                website_icons_enabled: true,
                ..DesktopSettings::default()
            },
        )
        .expect("enable icons");
        set_screen_capture_allowed_at(&path, true).expect("allow capture");
        assert!(screen_capture_allowed_at(&path));
        assert!(website_icons_enabled_at(&path));
        set_screen_capture_allowed_at(&path, false).expect("block capture");
        assert!(!screen_capture_allowed_at(&path));
        assert!(website_icons_enabled_at(&path));
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }

    #[test]
    fn turning_website_icons_off_keeps_the_screen_capture_choice() {
        let path = test_path("capture-icons-off");
        set_screen_capture_allowed_at(&path, true).expect("allow capture");
        assert!(set_website_icons_enabled_at(
            &path,
            false,
            &VaultState::default(),
            &ReleasePresence::default()
        )
        .is_ok());
        assert!(screen_capture_allowed_at(&path));
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }

    #[test]
    fn unreadable_or_oversized_settings_keep_screen_capture_blocked() {
        let path = test_path("capture-unreadable");
        fs::write(&path, b"not a settings file").expect("write settings");
        assert!(!screen_capture_allowed_at(&path));
        fs::write(&path, vec![b' '; (MAX_SETTINGS_BYTES + 1) as usize]).expect("write settings");
        assert!(!screen_capture_allowed_at(&path));
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }

    #[test]
    fn a_presence_grant_allows_enabling_website_icons() {
        let path = test_path("presence-granted");
        let (state, presence) = presence_granted_state();
        assert!(set_website_icons_enabled_at(&path, true, &state, &presence).is_ok());
        assert!(website_icons_enabled_at(&path));
        let _ = fs::remove_dir_all(path.parent().expect("settings parent"));
    }
}
