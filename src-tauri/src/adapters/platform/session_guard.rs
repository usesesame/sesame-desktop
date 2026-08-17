//! Clears the unlocked vault when Windows locks or the user is inactive.
//! Runs on system input independent of the webview: throttling or a suspended renderer cannot keep a vault open.

#[cfg(windows)]
use std::time::Duration;
#[cfg(windows)]
use tauri::{AppHandle, Emitter, Manager};

#[cfg(windows)]
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The warning exists because locking clears unsaved drafts; nothing the interface does can postpone the lock.
#[cfg(windows)]
const WARNING_WINDOW: Duration = Duration::from_secs(30);

#[cfg(windows)]
pub fn start(app: AppHandle) {
    #[cfg(feature = "wdio")]
    {
        // The installed-app runner has no physical input; only the input timer is absent here.
        drop(app);
    }
    #[cfg(not(feature = "wdio"))]
    std::thread::spawn(move || run(app));
}

#[cfg(not(windows))]
pub fn start(_app: tauri::AppHandle) {}

#[cfg(windows)]
fn run(app: AppHandle) {
    let mut was_locked = workstation_locked();
    let mut warning_shown = false;
    loop {
        std::thread::sleep(POLL_INTERVAL);
        let locked = workstation_locked();
        if locked && !was_locked {
            crate::desktop_shell::lock_vault_if_unlocked(&app);
            warning_shown = clear_warning(&app, warning_shown);
        } else if !locked {
            let timeout = Duration::from_secs(
                app.state::<crate::vault::VaultState>()
                    .auto_lock_minutes()
                    .saturating_mul(60),
            );
            match user_idle_for() {
                Some(idle) if idle >= timeout => {
                    crate::desktop_shell::lock_vault_if_unlocked(&app);
                    warning_shown = clear_warning(&app, warning_shown);
                }
                Some(idle) => {
                    warning_shown =
                        update_warning(&app, timeout.saturating_sub(idle), warning_shown);
                }
                // Withdraw a warning no longer backed by a measurement.
                None => warning_shown = clear_warning(&app, warning_shown),
            }
        }
        was_locked = locked;
    }
}

/// A locked vault has nothing to warn about; zero remaining means the lock is taken this poll.
#[cfg(windows)]
fn should_warn(remaining: Duration, session_open: bool) -> bool {
    session_open && !remaining.is_zero() && remaining <= WARNING_WINDOW
}

#[cfg(windows)]
fn update_warning(app: &AppHandle, remaining: Duration, warning_shown: bool) -> bool {
    if !should_warn(remaining, session_is_open(app)) {
        return clear_warning(app, warning_shown);
    }
    // Re-emitted each poll so the interface timer cannot drift from the one that decides.
    let _ = app.emit("vault-idle-warning", remaining.as_secs().max(1));
    true
}

#[cfg(windows)]
fn clear_warning(app: &AppHandle, warning_shown: bool) -> bool {
    if warning_shown {
        let _ = app.emit("vault-idle-warning-cleared", ());
    }
    false
}

#[cfg(windows)]
fn session_is_open(app: &AppHandle) -> bool {
    app.state::<crate::vault::VaultState>()
        .session
        .lock()
        .map(|session| session.is_some())
        .unwrap_or(false)
}

/// Wrapping subtraction stays correct across the 49-day tick-count rollover.
#[cfg(windows)]
fn user_idle_for() -> Option<Duration> {
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    let mut input = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    if unsafe { GetLastInputInfo(&mut input) } == 0 {
        return None;
    }
    let now = unsafe { GetTickCount() };
    Some(Duration::from_millis(now.wrapping_sub(input.dwTime) as u64))
}

/// The input desktop cannot be opened on the lock screen or another secure desktop.
#[cfg(windows)]
fn workstation_locked() -> bool {
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, OpenInputDesktop, DESKTOP_READOBJECTS,
    };

    let desktop = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
    if desktop.is_null() {
        true
    } else {
        unsafe { CloseDesktop(desktop) };
        false
    }
}
