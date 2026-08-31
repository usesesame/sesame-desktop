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
        account_linking: cfg!(windows),
        desktop_updates: cfg!(windows) || cfg!(target_os = "linux"),
        window_controls: cfg!(windows),
    }
}
