//! Reported to the interface so a platform without a facility hides it rather
//! than failing at the moment someone depends on it.

use serde::Serialize;

#[derive(Debug, Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct PlatformCapabilities {
    os: &'static str,
    pin_unlock: bool,
    biometric_unlock: bool,
    auto_type: bool,
    browser_integration: bool,
    session_auto_lock: bool,
    quick_access_shortcut: bool,
    account_linking: bool,
    desktop_updates: bool,
    window_controls: bool,
}

fn desktop_updates_for(os: &str) -> bool {
    os == "windows"
}

#[tauri::command]
pub fn get_platform_capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        os: std::env::consts::OS,
        pin_unlock: crate::vault::platform::device_protection_available(),
        biometric_unlock: cfg!(windows),
        auto_type: cfg!(windows),
        browser_integration: crate::browser_host::is_supported(),
        session_auto_lock: crate::session_guard::idle_auto_lock_available(),
        quick_access_shortcut: crate::desktop_shell::global_shortcut_available(),
        account_linking: crate::vault::platform::device_protection_available(),
        desktop_updates: desktop_updates_for(std::env::consts::OS),
        window_controls: cfg!(windows),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATING_SYSTEMS: [&str; 8] = [
        "windows", "linux", "macos", "ios", "android", "freebsd", "solaris", "",
    ];

    #[test]
    fn only_windows_reports_desktop_updates() {
        for os in OPERATING_SYSTEMS {
            assert_eq!(desktop_updates_for(os), os == "windows", "{os:?}");
        }
    }

    #[test]
    fn the_update_flag_agrees_with_the_updater_platform_check() {
        for os in OPERATING_SYSTEMS {
            assert_eq!(
                desktop_updates_for(os),
                crate::commands::updater::updater_platform_for(os).is_ok(),
                "{os:?}"
            );
        }
        assert_eq!(
            get_platform_capabilities().desktop_updates,
            crate::commands::updater::updater_platform_for(std::env::consts::OS).is_ok()
        );
    }

    #[test]
    fn the_reported_flag_follows_the_running_system() {
        assert_eq!(
            get_platform_capabilities().desktop_updates,
            desktop_updates_for(std::env::consts::OS)
        );
    }

    #[test]
    fn account_linking_follows_device_protection() {
        assert_eq!(
            get_platform_capabilities().account_linking,
            crate::vault::platform::device_protection_available()
        );
    }
}
