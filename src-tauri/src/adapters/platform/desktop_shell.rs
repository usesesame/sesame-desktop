use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::Duration;

use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    webview::NewWindowResponse,
    App, AppHandle, LogicalSize, Manager, PhysicalSize, State, WebviewUrl, WebviewWindow,
    WebviewWindowBuilder, Window, WindowEvent,
};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_global_shortcut::GlobalShortcutExt;

use crate::adapters::platform::webview_policy::{
    display_affinity, DisplayAffinity, WEBVIEW2_BROWSER_ARGUMENTS,
};
use crate::desktop_settings;
use crate::vault::VaultState;

/// Boot-time launches stay in the tray instead of popping the window open.
pub const MINIMIZED_LAUNCH_ARG: &str = "--minimized";

pub const QUICK_ACCESS_SHORTCUT: &str = "Ctrl+Alt+S";
const MAIN_MIN_WIDTH: f64 = 860.0;
const MAIN_MIN_HEIGHT: f64 = 600.0;

static QUITTING: AtomicBool = AtomicBool::new(false);

const BLUR_GRACE: Duration = Duration::from_millis(1200);
const BLUR_POINTER_LINGER: Duration = Duration::from_secs(8);
const BLUR_POLL: Duration = Duration::from_millis(100);

static WATCHING_BLUR: AtomicBool = AtomicBool::new(false);

#[derive(Debug, PartialEq, Eq)]
enum BlurStep {
    Wait,
    Hide,
    Stop,
}

fn blur_step(lost_for: Duration, focused: bool, visible: bool, pointer_inside: bool) -> BlurStep {
    if focused || !visible {
        return BlurStep::Stop;
    }
    let allowed = if pointer_inside {
        BLUR_POINTER_LINGER
    } else {
        BLUR_GRACE
    };
    if lost_for >= allowed {
        BlurStep::Hide
    } else {
        BlurStep::Wait
    }
}

fn contains_point(
    point: tauri::PhysicalPosition<f64>,
    origin: tauri::PhysicalPosition<i32>,
    size: PhysicalSize<u32>,
) -> bool {
    point.x >= f64::from(origin.x)
        && point.y >= f64::from(origin.y)
        && point.x < f64::from(origin.x) + f64::from(size.width)
        && point.y < f64::from(origin.y) + f64::from(size.height)
}

fn pointer_over(window: &Window) -> bool {
    match (
        window.cursor_position(),
        window.outer_position(),
        window.outer_size(),
    ) {
        (Ok(point), Ok(origin), Ok(size)) => contains_point(point, origin, size),
        _ => false,
    }
}

fn hide_when_focus_stays_lost(window: Window) {
    if WATCHING_BLUR.swap(true, Ordering::AcqRel) {
        return;
    }
    std::thread::spawn(move || {
        let mut lost_for = Duration::ZERO;
        loop {
            std::thread::sleep(BLUR_POLL);
            lost_for += BLUR_POLL;
            let step = blur_step(
                lost_for,
                window.is_focused().unwrap_or(false),
                window.is_visible().unwrap_or(false),
                pointer_over(&window),
            );
            match step {
                BlurStep::Wait => continue,
                BlurStep::Hide => {
                    let _ = window.hide();
                    break;
                }
                BlurStep::Stop => break,
            }
        }
        WATCHING_BLUR.store(false, Ordering::Release);
    });
}

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
    let quick_access =
        MenuItemBuilder::with_id("sesame.quick-access", "Quick access").build(app)?;
    let lock = MenuItemBuilder::with_id("sesame.lock", "Lock vault").build(app)?;
    let quit = MenuItemBuilder::with_id("sesame.quit", "Quit Sesame").build(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[&open, &quick_access, &lock, &quit])
        .build()?;

    let mut tray = TrayIconBuilder::with_id("sesame-tray")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("Sesame local vault")
        .on_menu_event(|app, event| match event.id().as_ref() {
            "sesame.open" => show_main_window(app),
            "sesame.quick-access" => toggle_quick_access(app),
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

    let quick_access_configured = app
        .config()
        .app
        .windows
        .iter()
        .any(|window| window.label == "quick-access");
    if quick_access_configured {
        ensure_quick_access_window(app.handle()).ok_or_else(|| {
            tauri::Error::Io(std::io::Error::other(
                "Sesame could not prepare the quick access window.",
            ))
        })?;
    }
    ensure_main_window(app.handle()).ok_or_else(|| {
        tauri::Error::Io(std::io::Error::other(
            "Sesame could not prepare the main window.",
        ))
    })?;

    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_min_size(Some(LogicalSize::new(MAIN_MIN_WIDTH, MAIN_MIN_HEIGHT)));
        secure_window(&window).map_err(|error| tauri::Error::Io(std::io::Error::other(error)))?;
    }
    if let Some(window) = app.get_webview_window("quick-access") {
        secure_window(&window).map_err(|error| tauri::Error::Io(std::io::Error::other(error)))?;
    }

    // Hidden by default so startup-entry launches stay in the tray; other launches show once.
    let launched_minimized = std::env::args().any(|arg| arg == MINIMIZED_LAUNCH_ARG);
    if !launched_minimized {
        show_main_window(app.handle());
    }
    Ok(())
}

pub fn global_shortcut_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux_global_shortcut_available(
            std::env::var_os("GDK_BACKEND").as_deref(),
            std::env::var_os("WAYLAND_DISPLAY").as_deref(),
            std::env::var_os("XDG_SESSION_TYPE").as_deref(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

#[cfg(target_os = "linux")]
fn linux_global_shortcut_available(
    gdk_backend: Option<&std::ffi::OsStr>,
    wayland_display: Option<&std::ffi::OsStr>,
    session_type: Option<&std::ffi::OsStr>,
) -> bool {
    if gdk_backend.is_some_and(|backend| backend.to_string_lossy().contains("x11")) {
        return true;
    }
    let wayland_session = wayland_display.is_some()
        || session_type.is_some_and(|value| value.eq_ignore_ascii_case("wayland"));
    !wayland_session
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
    // Losing focus for good closes the popup so decrypted titles never linger on screen unattended.
    // A short loss, such as a window manager that follows the pointer, does not.
    if window.label() == "quick-access" {
        if let WindowEvent::Focused(false) = event {
            hide_when_focus_stays_lost(window.clone());
        }
        return;
    }
    if let WindowEvent::Focused(focused) = event {
        if let Some(fill) = window
            .app_handle()
            .try_state::<crate::browser_fill::BrowserFillState>()
        {
            fill.window_focus_changed(*focused);
        }
    }
    if let WindowEvent::Resized(size) = event {
        let scale = window.scale_factor().unwrap_or(1.0);
        if let Some(size) = bounded_main_size(*size, scale) {
            let _ = window.set_size(size);
        }
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

fn bounded_main_size(size: PhysicalSize<u32>, scale: f64) -> Option<PhysicalSize<u32>> {
    let minimum_width = (MAIN_MIN_WIDTH * scale).round() as u32;
    let minimum_height = (MAIN_MIN_HEIGHT * scale).round() as u32;
    (size.width < minimum_width || size.height < minimum_height).then(|| {
        PhysicalSize::new(
            size.width.max(minimum_width),
            size.height.max(minimum_height),
        )
    })
}

pub fn toggle_quick_access(app: &AppHandle) {
    let Some(window) = ensure_quick_access_window(app) else {
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
    if !global_shortcut_available() {
        return Err(
            "This desktop session does not support a global shortcut. Open quick access from the Sesame tray icon."
                .to_string(),
        );
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
        .min_inner_size(MAIN_MIN_WIDTH, MAIN_MIN_HEIGHT)
        .resizable(true)
        .decorations(false)
        .visible(false)
        .additional_browser_args(WEBVIEW2_BROWSER_ARGUMENTS)
        .general_autofill_enabled(false)
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .build()
        .ok()?;
    if secure_window(&window).is_err() {
        let _ = window.destroy();
        return None;
    }
    Some(window)
}

pub(crate) fn ensure_quick_access_window(app: &AppHandle) -> Option<WebviewWindow> {
    if let Some(window) = app.get_webview_window("quick-access") {
        return Some(window);
    }
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == "quick-access")?
        .clone();
    let window = WebviewWindowBuilder::from_config(app, &config)
        .ok()?
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .build()
        .ok()?;
    if secure_window(&window).is_err() {
        let _ = window.destroy();
        return None;
    }
    Some(window)
}

fn secure_window(window: &WebviewWindow) -> Result<(), String> {
    harden_release_webview(window);
    let capture_allowed = desktop_settings::settings_path(window.app_handle())
        .is_ok_and(|path| desktop_settings::screen_capture_allowed_at(&path));
    set_display_affinity(window, display_affinity(capture_allowed))
}

pub(crate) fn apply_capture_policy(app: &AppHandle, capture_allowed: bool) -> Result<(), String> {
    let failed: Vec<&str> = ["main", "quick-access"]
        .into_iter()
        .filter(|label| {
            app.get_webview_window(label).is_some_and(|window| {
                set_display_affinity(&window, display_affinity(capture_allowed)).is_err()
            })
        })
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Windows did not change the screen capture setting for the {} window.",
            failed.join(" and ")
        ))
    }
}

#[cfg(windows)]
fn set_display_affinity(window: &WebviewWindow, affinity: DisplayAffinity) -> Result<(), String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE,
    };

    let hwnd = window
        .hwnd()
        .map_err(|error| format!("The window handle is unavailable: {error}"))?;
    let value = match affinity {
        DisplayAffinity::ExcludeFromCapture => WDA_EXCLUDEFROMCAPTURE,
        DisplayAffinity::Unrestricted => WDA_NONE,
    };
    let changed = unsafe { SetWindowDisplayAffinity(hwnd.0 as _, value) };
    if changed == 0 {
        return Err("SetWindowDisplayAffinity failed.".to_string());
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_display_affinity(_window: &WebviewWindow, _affinity: DisplayAffinity) -> Result<(), String> {
    Ok(())
}

#[cfg(all(windows, not(debug_assertions)))]
fn harden_release_webview(window: &WebviewWindow) {
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings3;
    use windows_core::Interface;

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
            if let Ok(settings) = settings.cast::<ICoreWebView2Settings3>() {
                let _ = settings.SetAreBrowserAcceleratorKeysEnabled(false);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_loss_of_focus_does_not_hide_the_quick_access_window() {
        let brief = Duration::from_millis(300);
        assert_eq!(blur_step(brief, false, true, false), BlurStep::Wait);
        assert_eq!(blur_step(BLUR_GRACE, false, true, false), BlurStep::Hide);
    }

    #[test]
    fn regaining_focus_or_being_hidden_already_ends_the_wait() {
        assert_eq!(blur_step(Duration::ZERO, true, true, false), BlurStep::Stop);
        assert_eq!(blur_step(BLUR_GRACE, false, false, false), BlurStep::Stop);
    }

    #[test]
    fn a_pointer_over_the_window_gets_longer_but_never_forever() {
        assert_eq!(blur_step(BLUR_GRACE, false, true, true), BlurStep::Wait);
        assert_eq!(
            blur_step(BLUR_POINTER_LINGER, false, true, true),
            BlurStep::Hide
        );
        assert!(BLUR_POINTER_LINGER > BLUR_GRACE);
    }

    #[test]
    fn the_pointer_is_over_a_window_only_inside_its_edges() {
        let origin = tauri::PhysicalPosition::new(100, 50);
        let size = PhysicalSize::new(460, 440);
        let at = |x: f64, y: f64| contains_point(tauri::PhysicalPosition::new(x, y), origin, size);
        assert!(at(100.0, 50.0));
        assert!(at(559.9, 489.9));
        assert!(!at(560.0, 100.0));
        assert!(!at(300.0, 490.0));
        assert!(!at(99.0, 100.0));
        assert!(!at(300.0, 49.0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_wayland_session_reports_no_global_shortcut() {
        use std::ffi::OsStr;

        assert!(!linux_global_shortcut_available(
            None,
            Some(OsStr::new("wayland-1")),
            Some(OsStr::new("wayland"))
        ));
        assert!(!linux_global_shortcut_available(
            None,
            None,
            Some(OsStr::new("Wayland"))
        ));
        assert!(linux_global_shortcut_available(
            None,
            None,
            Some(OsStr::new("x11"))
        ));
        assert!(linux_global_shortcut_available(None, None, None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forcing_the_gtk_backend_to_x11_restores_the_global_shortcut() {
        use std::ffi::OsStr;

        assert!(linux_global_shortcut_available(
            Some(OsStr::new("x11")),
            Some(OsStr::new("wayland-1")),
            Some(OsStr::new("wayland"))
        ));
        assert!(!linux_global_shortcut_available(
            Some(OsStr::new("wayland")),
            Some(OsStr::new("wayland-1")),
            Some(OsStr::new("wayland"))
        ));
    }

    #[test]
    fn main_window_size_never_falls_below_the_usable_floor() {
        assert_eq!(
            bounded_main_size(PhysicalSize::new(800, 550), 1.0),
            Some(PhysicalSize::new(860, 600))
        );
        assert_eq!(bounded_main_size(PhysicalSize::new(1200, 800), 1.0), None);
        assert_eq!(
            bounded_main_size(PhysicalSize::new(1500, 900), 2.0),
            Some(PhysicalSize::new(1720, 1200))
        );
    }
}
