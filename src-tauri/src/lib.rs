// Tests opt out of `unwrap_used`: a panic in a test is a correct failure report.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod adapters;
mod browser_fill;
mod browser_protocol;
mod commands;
#[cfg(feature = "wdio")]
mod desktop_e2e;
mod diagnostics;
mod sync;
mod vault;

pub(crate) use adapters::network::website_icons;
pub(crate) use adapters::platform::{
    app_identity, browser_host, browser_pipe, clipboard, crash_protection, desktop_shell,
    dll_search, session_guard,
};

#[allow(unused_imports)]
use vault::*;

#[allow(unused_imports)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[allow(unused_imports)]
use std::fs;
#[allow(unused_imports)]
use zeroize::{Zeroize, Zeroizing};

/// Base commands plus `sync-preview`-only extras; release builds expose no Sync command.
macro_rules! sesame_invoke_handler {
    ($($extra:path),* $(,)?) => {
        tauri::generate_handler![
            commands::get_vault_status,
            commands::create_vault,
            commands::resume_recovery_setup,
            commands::complete_recovery_setup,
            commands::unlock_vault,
            commands::change_master_password,
            commands::unlock_recovery_vault,
            commands::set_unlock_pin,
            commands::remove_unlock_pin,
            commands::unlock_pin_vault,
            commands::enable_windows_hello,
            commands::disable_windows_hello,
            commands::unlock_with_windows_hello,
            commands::set_auto_lock_minutes,
            commands::get_vault_snapshot,
            commands::get_quick_access_status,
            commands::search_quick_access_entries,
            commands::get_quick_access_secret,
            commands::get_login_card,
            commands::search_entries,
            commands::suggest_field_values,
            commands::check_password_strength,
            commands::check_password_breach,
            commands::auto_type,
            commands::get_login_summary,
            commands::get_duplicate_groups,
            commands::refresh_totp,
            commands::list_totp_codes,
            commands::save_login,
            commands::set_login_folders,
            commands::bulk_assign_folder,
            commands::create_folder,
            commands::rename_folder,
            commands::delete_folder,
            commands::set_login_favourite,
            commands::record_login_use,
            commands::delete_login,
            commands::get_identity,
            commands::save_identity,
            commands::delete_identity,
            commands::get_secure_note,
            commands::save_secure_note,
            commands::delete_secure_note,
            commands::get_card,
            commands::save_card,
            commands::delete_card,
            commands::get_wifi_network,
            commands::save_wifi_network,
            commands::delete_wifi_network,
            commands::get_ssh_key,
            commands::save_ssh_key,
            commands::delete_ssh_key,
            commands::get_software_license,
            commands::save_software_license,
            commands::delete_software_license,
            commands::get_document,
            commands::save_document,
            commands::delete_document,
            commands::add_document_attachment,
            commands::remove_document_attachment,
            commands::get_custom_record,
            commands::save_custom_record,
            commands::delete_custom_record,
            commands::preview_trashed_item,
            commands::restore_trashed_item,
            commands::preview_history_version,
            commands::restore_history_version,
            commands::merge_duplicate_logins,
            commands::get_merge_comparison,
            commands::preview_import,
            commands::commit_import,
            commands::cancel_import,
            commands::create_backup,
            commands::export_backup,
            commands::export_vault_csv,
            commands::export_recovery_kit,
            commands::delete_local_vault,
            commands::inspect_backup,
            commands::verify_backup,
            commands::restore_backup,
            commands::lock_vault,
            commands::get_recovery_health,
            commands::link_desktop_service,
            commands::get_service_connection_status,
            commands::disconnect_service,
            commands::check_desktop_update,
            commands::download_and_install_desktop_update,
            commands::record_diagnostic,
            commands::get_diagnostic_status,
            commands::export_diagnostics,
            commands::clear_diagnostics,
            adapters::platform::external_url::open_external_url,
            commands::get_browser_integration_status,
            commands::repair_browser_integration,
            commands::get_pending_browser_fill,
            commands::resolve_browser_fill,
            commands::get_pending_browser_save,
            commands::resolve_browser_save,
            commands::get_pending_browser_identity_fill,
            commands::resolve_browser_identity_fill,
            commands::get_pending_browser_card_fill,
            commands::resolve_browser_card_fill,
            clipboard::arm_clipboard_clear,
            clipboard::clear_clipboard_if_unchanged,
            desktop_shell::set_tray_enabled,
            desktop_shell::set_quick_access_shortcut,
            desktop_shell::get_autostart_enabled,
            desktop_shell::set_autostart_enabled,
            website_icons::get_website_icon,
            website_icons::clear_website_icon_cache,
            website_icons::get_website_icon_cache_status,
            $($extra,)*
        ]
    };
}

/// Two macros because `generate_handler!`'s closure type is only inferable inline.
#[cfg(feature = "sync-preview")]
macro_rules! sesame_handler {
    () => {
        sesame_invoke_handler![
            commands::sync::sync_status,
            commands::sync::sync_enroll_device,
            commands::sync::sync_this_device_fingerprint,
            commands::sync::sync_disable,
            commands::sync::sync_prepare_approval,
            commands::sync::sync_approve_prepared_device,
            commands::sync_transfer::sync_upload_vault,
            commands::sync_transfer::sync_download_vault,
            commands::sync_transfer::sync_conflict_details,
            commands::sync_transfer::sync_resolve_conflict,
            commands::sync_transfer::sync_list_conflict_backups,
            commands::sync_transfer::sync_restore_conflict_backup,
            commands::sync_transfer::sync_remove_device,
            commands::sync_transfer::sync_deny_device,
            commands::sync_transfer::sync_activate_device,
            commands::sync_transfer::sync_reset_vault,
            commands::sync_transfer::sync_coordinator_status,
            commands::sync_transfer::sync_now,
            commands::sync_adopt::sync_adopt_vault,
        ]
    };
}

#[cfg(not(feature = "sync-preview"))]
macro_rules! sesame_handler {
    () => {
        sesame_invoke_handler![]
    };
}

#[cfg(all(feature = "wdio", feature = "sync-preview"))]
macro_rules! sesame_wdio_handler {
    () => {
        sesame_invoke_handler![
            desktop_e2e::desktop_e2e_config,
            commands::sync::sync_status,
            commands::sync::sync_enroll_device,
            commands::sync::sync_this_device_fingerprint,
            commands::sync::sync_disable,
            commands::sync::sync_prepare_approval,
            commands::sync::sync_approve_prepared_device,
            commands::sync_transfer::sync_upload_vault,
            commands::sync_transfer::sync_download_vault,
            commands::sync_transfer::sync_conflict_details,
            commands::sync_transfer::sync_resolve_conflict,
            commands::sync_transfer::sync_list_conflict_backups,
            commands::sync_transfer::sync_restore_conflict_backup,
            commands::sync_transfer::sync_remove_device,
            commands::sync_transfer::sync_deny_device,
            commands::sync_transfer::sync_activate_device,
            commands::sync_transfer::sync_reset_vault,
            commands::sync_transfer::sync_coordinator_status,
            commands::sync_transfer::sync_now,
            commands::sync_adopt::sync_adopt_vault,
        ]
    };
}

#[cfg(all(feature = "wdio", not(feature = "sync-preview")))]
macro_rules! sesame_wdio_handler {
    () => {
        sesame_invoke_handler![desktop_e2e::desktop_e2e_config]
    };
}

#[cfg(all(windows, not(debug_assertions)))]
const WEBVIEW2_DEBUG_ENVIRONMENT_VARIABLES: [&str; 3] = [
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
    "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
];

#[cfg(all(windows, not(debug_assertions)))]
fn prepare_release_webview_environment() {
    for variable in WEBVIEW2_DEBUG_ENVIRONMENT_VARIABLES {
        std::env::remove_var(variable);
    }
}

#[cfg(any(not(windows), debug_assertions))]
fn prepare_release_webview_environment() {}

pub fn run() {
    // Before Tauri or WebView2 loads any optional DLL; a failure restores the unsafe search path.
    if dll_search::harden_process().is_err() {
        std::process::exit(1);
    }
    if crash_protection::harden_process().is_err() {
        std::process::exit(1);
    }
    prepare_release_webview_environment();
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![desktop_shell::MINIMIZED_LAUNCH_ARG]),
        ))
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    if event.state == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                        desktop_shell::toggle_quick_access(app);
                    }
                })
                .build(),
        )
        .manage(vault::VaultState::default())
        .manage(browser_fill::BrowserFillState::default())
        .manage(desktop_shell::DesktopShellState::default())
        .manage(clipboard::ClipboardGuard::default())
        // Managed only in a preview build, like every other part of Sync.
        .manage({
            #[cfg(feature = "sync-preview")]
            {
                sync::coordinator::Coordinator::new()
            }
            #[cfg(not(feature = "sync-preview"))]
            {
                ()
            }
        })
        .setup(|app| {
            if let Some(public_key) =
                adapters::network::public_updates::updater_public_key_if_configured()
            {
                app.handle().plugin(
                    tauri_plugin_updater::Builder::new()
                        .pubkey(public_key)
                        .build(),
                )?;
            }
            diagnostics::install_panic_hook(app.handle().clone());
            desktop_shell::setup(app)?;
            {
                use tauri_plugin_global_shortcut::GlobalShortcutExt;
                let _ = app
                    .global_shortcut()
                    .register(desktop_shell::QUICK_ACCESS_SHORTCUT);
            }
            match browser_host::register(app.handle()) {
                Ok(_) => {
                    diagnostics::record_browser_host_registration(app.handle(), "registration_ok")
                }
                Err(error) => diagnostics::record_browser_host_registration(
                    app.handle(),
                    error.diagnostic_code(),
                ),
            }
            if browser_fill::start(app.handle().clone()).is_err() {
                diagnostics::record_browser_host_registration(app.handle(), "pipe_server_failed");
            }
            session_guard::start(app.handle().clone());
            Ok(())
        })
        .on_window_event(desktop_shell::handle_window_event);

    #[cfg(feature = "wdio")]
    let builder = builder.invoke_handler(sesame_wdio_handler!());
    #[cfg(not(feature = "wdio"))]
    let builder = builder.invoke_handler(sesame_handler!());

    builder
        .build(tauri::generate_context!())
        .expect("error while building Sesame desktop application")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
                desktop_shell::lock_vault_if_unlocked(app);
                browser_fill::cancel_pending_approvals(app);
            }
        });
}

pub fn run_browser_host() {
    // Same DLL search hardening before the sidecar's first native-messaging request.
    if dll_search::harden_process().is_err() {
        std::process::exit(1);
    }
    if crash_protection::harden_process().is_err() {
        std::process::exit(1);
    }
    browser_host::run();
}
