use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    App, AppHandle, Manager, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder, Window,
    WindowEvent,
};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_global_shortcut::GlobalShortcutExt;

use crate::vault::VaultState;

/// Boot-time launches stay in the tray instead of popping the window open.
pub const MINIMIZED_LAUNCH_ARG: &str = "--minimized";

pub const QUICK_ACCESS_SHORTCUT: &str = "Ctrl+Alt+S";

static QUITTING: AtomicBool = AtomicBool::new(false);

pub struct DesktopShellState {
    close_to_tray: AtomicBool,
    /// Rust owns the registered accelerator: a change must succeed against the OS first.
    active_shortcut: Mutex<String>,
}

impl Default for DesktopShellState {
    fn default() -> Self {
        Self {
            close_to_tray: AtomicBool::new(true),
            active_shortcut: Mutex::new(QUICK_ACCESS_SHORTCUT.to_string()),
        }
    }
}

pub fn setup(app: &mut App) -> tauri::Result<()> {
    let open = MenuItemBuilder::with_id("sesame.open", "Open Sesame").build(app)?;
    let lock = MenuItemBuilder::with_id("sesame.lock", "Lock vault").build(app)?;
    let quit = MenuItemBuilder::with_id("sesame.quit", "Quit Sesame").build(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[&open, &lock, &quit])
        .build()?;

    let mut tray = TrayIconBuilder::with_id("sesame-tray")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("Sesame local vault")
        .on_menu_event(|app, event| match event.id().as_ref() {
            "sesame.open" => show_main_window(app),
            "sesame.lock" => lock_vault(app),
            "sesame.quit" => {
                QUITTING.store(true, Ordering::Release);
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                }
            ) {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon().cloned() {
        tray = tray.icon(icon);
    }
    tray.build(app)?;

    if let Some(window) = app.get_webview_window("main") {
        harden_release_webview(&window);
    }
    if let Some(window) = app.get_webview_window("quick-access") {
        harden_release_webview(&window);
    }

    // Hidden by default so startup-entry launches stay in the tray; other launches show once.
    let launched_minimized = std::env::args().any(|arg| arg == MINIMIZED_LAUNCH_ARG);
    if !launched_minimized {
        show_main_window(app.handle());
    }
    Ok(())
}

#[tauri::command]
pub fn get_autostart_enabled(app: AppHandle) -> Result<bool, String> {
    app.autolaunch()
        .is_enabled()
        .map_err(|_| "Sesame could not read the startup setting.".to_string())
}

#[tauri::command]
pub fn set_autostart_enabled(app: AppHandle, enabled: bool) -> Result<(), String> {
    let autostart = app.autolaunch();
    if enabled {
        autostart.enable()
    } else {
        autostart.disable()
    }
    .map_err(|_| "Sesame could not update the startup setting.".to_string())
}

pub fn handle_window_event(window: &Window, event: &WindowEvent) {
    // Losing focus closes the popup so decrypted titles never linger on screen unattended.
    if window.label() == "quick-access" {
        if let WindowEvent::Focused(false) = event {
            let _ = window.hide();
        }
        return;
    }
    if let WindowEvent::CloseRequested { api, .. } = event {
        let close_to_tray = window
            .app_handle()
            .state::<DesktopShellState>()
            .close_to_tray
            .load(Ordering::Acquire);
        if close_to_tray && !QUITTING.load(Ordering::Acquire) {
            api.prevent_close();
            let _ = window.hide();
        }
    }
}

pub fn toggle_quick_access(app: &AppHandle) {
    let Some(window) = app.get_webview_window("quick-access") else {
        return;
    };
    let already_focused = window.is_focused().unwrap_or(false);
    if already_focused {
        let _ = window.hide();
    } else {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
pub fn set_tray_enabled(
    app: AppHandle,
    state: State<'_, DesktopShellState>,
    enabled: bool,
) -> Result<(), String> {
    let tray = app
        .tray_by_id("sesame-tray")
        .ok_or("Sesame could not find its tray icon.")?;
    tray.set_visible(enabled)
        .map_err(|_| "Sesame could not update the tray icon.".to_string())?;
    state.close_to_tray.store(enabled, Ordering::Release);
    Ok(())
}

/// Register first so a failed change leaves the previous shortcut working.
#[tauri::command]
pub fn set_quick_access_shortcut(
    app: AppHandle,
    state: State<'_, DesktopShellState>,
    shortcut: String,
) -> Result<(), String> {
    let trimmed = shortcut.trim();
    if trimmed.is_empty() {
        return Err("Choose a key combination first.".to_string());
    }
    let mut active = state
        .active_shortcut
        .lock()
        .map_err(|_| "Sesame could not read the current shortcut.".to_string())?;
    if *active == trimmed {
        return Ok(());
    }
    app.global_shortcut().register(trimmed).map_err(|_| {
        "Sesame could not use that combination. Another program may already use it.".to_string()
    })?;
    let _ = app.global_shortcut().unregister(active.as_str());
    *active = trimmed.to_string();
    Ok(())
}

pub(crate) fn show_main_window(app: &AppHandle) {
    if let Some(window) = ensure_main_window(app) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Rebuilds "main" if it was destroyed; callers must not assume it always exists.
pub(crate) fn ensure_main_window(app: &AppHandle) -> Option<WebviewWindow> {
    if let Some(window) = app.get_webview_window("main") {
        return Some(window);
    }
    let window = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Sesame")
        .inner_size(1360.0, 860.0)
        .min_inner_size(1000.0, 700.0)
        .resizable(true)
        .decorations(false)
        .visible(false)
        .build()
        .ok()?;
    harden_release_webview(&window);
    Some(window)
}

#[cfg(all(windows, not(debug_assertions)))]
fn harden_release_webview(window: &WebviewWindow) {
    let _ = window.with_webview(|platform| {
        // SAFETY: WebView2 owns these COM interfaces for the platform handle's lifetime.
        unsafe {
            let Ok(webview) = platform.controller().CoreWebView2() else {
                return;
            };
            let Ok(settings) = webview.Settings() else {
                return;
            };
            let _ = settings.SetAreDefaultContextMenusEnabled(false);
            let _ = settings.SetAreDevToolsEnabled(false);
        }
    });
}

#[cfg(any(not(windows), debug_assertions))]
fn harden_release_webview(_window: &WebviewWindow) {}

pub fn lock_vault(app: &AppHandle) {
    let state = app.state::<VaultState>();
    let _ = crate::vault::lock_and_notify(&state, app);
}

/// No spurious lock events when the vault is already locked.
pub fn lock_vault_if_unlocked(app: &AppHandle) -> bool {
    let has_session = app
        .state::<VaultState>()
        .session
        .lock()
        .map(|session| session.is_some())
        .unwrap_or(false);
    if has_session {
        lock_vault(app);
    }
    has_session
}
