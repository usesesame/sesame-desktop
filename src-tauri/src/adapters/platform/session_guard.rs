//! Clears the unlocked vault when the desktop session locks or the user is inactive.
//! Runs on system input independent of the webview: throttling or a suspended renderer cannot keep a vault open.

#[cfg(any(windows, target_os = "linux"))]
mod monitor {
    use std::time::Duration;

    use tauri::{AppHandle, Emitter, Manager};

    pub(super) const POLL_INTERVAL: Duration = Duration::from_secs(1);
    pub(super) const WARNING_WINDOW: Duration = Duration::from_secs(30);

    pub(super) trait SessionMonitor: Send + 'static {
        fn locked(&self) -> bool;
        fn idle_for(&self) -> Option<Duration>;
    }

    pub(super) fn run<M: SessionMonitor>(app: AppHandle, monitor: M) {
        let mut was_locked = monitor.locked();
        let mut warning_shown = false;
        loop {
            std::thread::sleep(POLL_INTERVAL);
            let locked = monitor.locked();
            if locked && !was_locked {
                crate::desktop_shell::lock_vault_if_unlocked(&app);
                warning_shown = clear_warning(&app, warning_shown);
            } else if !locked {
                let timeout = Duration::from_secs(
                    app.state::<crate::vault::VaultState>()
                        .auto_lock_minutes()
                        .saturating_mul(60),
                );
                match monitor.idle_for() {
                    Some(idle) if idle >= timeout => {
                        crate::desktop_shell::lock_vault_if_unlocked(&app);
                        warning_shown = clear_warning(&app, warning_shown);
                    }
                    Some(idle) => {
                        warning_shown =
                            update_warning(&app, timeout.saturating_sub(idle), warning_shown);
                    }
                    None => warning_shown = clear_warning(&app, warning_shown),
                }
            }
            was_locked = locked;
        }
    }

    pub(super) fn should_warn(remaining: Duration, session_open: bool) -> bool {
        session_open && !remaining.is_zero() && remaining <= WARNING_WINDOW
    }

    fn update_warning(app: &AppHandle, remaining: Duration, warning_shown: bool) -> bool {
        if !should_warn(remaining, session_is_open(app)) {
            return clear_warning(app, warning_shown);
        }
        let _ = app.emit("vault-idle-warning", remaining.as_secs().max(1));
        true
    }

    fn clear_warning(app: &AppHandle, warning_shown: bool) -> bool {
        if warning_shown {
            let _ = app.emit("vault-idle-warning-cleared", ());
        }
        false
    }

    fn session_is_open(app: &AppHandle) -> bool {
        app.state::<crate::vault::VaultState>()
            .session
            .lock()
            .map(|session| session.is_some())
            .unwrap_or(false)
    }
}

#[cfg(windows)]
pub fn start(app: tauri::AppHandle) {
    #[cfg(feature = "wdio")]
    {
        drop(app);
    }
    #[cfg(not(feature = "wdio"))]
    std::thread::spawn(move || monitor::run(app, windows_session::Session));
}

#[cfg(target_os = "linux")]
pub fn start(app: tauri::AppHandle) {
    #[cfg(feature = "wdio")]
    {
        drop(app);
    }
    #[cfg(not(feature = "wdio"))]
    {
        let session = linux_session::Session::connect();
        linux_session::record_idle_support(session.has_idle_source());
        if session.is_usable() {
            std::thread::spawn(move || monitor::run(app, session));
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn start(_app: tauri::AppHandle) {}

pub fn idle_auto_lock_available() -> bool {
    #[cfg(windows)]
    {
        true
    }
    #[cfg(target_os = "linux")]
    {
        linux_session::idle_supported()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

#[cfg(windows)]
mod windows_session {
    use std::time::Duration;

    pub struct Session;

    impl super::monitor::SessionMonitor for Session {
        /// The input desktop cannot be opened on the lock screen or another secure desktop.
        fn locked(&self) -> bool {
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

        /// Wrapping subtraction stays correct across the 49-day tick-count rollover.
        fn idle_for(&self) -> Option<Duration> {
            use windows_sys::Win32::System::SystemInformation::GetTickCount;
            use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
                GetLastInputInfo, LASTINPUTINFO,
            };

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
    }
}

/// Each signal is probed once at startup and the source that answered is kept.
/// A probe that cannot tell reports nothing rather than guessing.
#[cfg(target_os = "linux")]
mod linux_session {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use zbus::blocking::Connection;
    use zbus::zvariant::OwnedObjectPath;

    const LOGIND: &str = "org.freedesktop.login1";
    const LOGIND_PATH: &str = "/org/freedesktop/login1";
    const LOGIND_MANAGER: &str = "org.freedesktop.login1.Manager";
    const LOGIND_SESSION: &str = "org.freedesktop.login1.Session";
    const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
    const SCREENSAVER: &str = "org.freedesktop.ScreenSaver";
    const SCREENSAVER_PATH: &str = "/org/freedesktop/ScreenSaver";
    const KDE_SCREENSAVER_PATH: &str = "/ScreenSaver";
    const MUTTER: &str = "org.gnome.Mutter.IdleMonitor";
    const MUTTER_PATH: &str = "/org/gnome/Mutter/IdleMonitor/Core";

    static IDLE_SUPPORTED: AtomicBool = AtomicBool::new(false);

    pub fn record_idle_support(supported: bool) {
        IDLE_SUPPORTED.store(supported, Ordering::Release);
    }

    pub fn idle_supported() -> bool {
        IDLE_SUPPORTED.load(Ordering::Acquire)
    }

    enum Idle {
        /// Milliseconds.
        Mutter,
        /// Seconds.
        Kde,
    }

    pub struct Session {
        system: Option<Connection>,
        bus: Option<Connection>,
        logind: Option<OwnedObjectPath>,
        screensaver: Option<&'static str>,
        idle: Option<Idle>,
    }

    impl Session {
        pub fn connect() -> Session {
            let system = Connection::system().ok();
            let bus = Connection::session().ok();
            let logind = system.as_ref().and_then(logind_session_path);
            let screensaver = bus.as_ref().and_then(screensaver_path);
            let idle = bus.as_ref().and_then(|bus| {
                if mutter_idle(bus).is_some() {
                    Some(Idle::Mutter)
                } else if kde_idle(bus).is_some() {
                    Some(Idle::Kde)
                } else {
                    None
                }
            });
            Session {
                system,
                bus,
                logind,
                screensaver,
                idle,
            }
        }

        pub fn has_idle_source(&self) -> bool {
            self.idle.is_some()
        }

        pub fn is_usable(&self) -> bool {
            self.logind.is_some() || self.screensaver.is_some() || self.idle.is_some()
        }
    }

    impl super::monitor::SessionMonitor for Session {
        fn locked(&self) -> bool {
            let logind = self.system.as_ref().and_then(|system| {
                self.logind
                    .as_ref()
                    .and_then(|path| logind_locked_hint(system, path))
            });
            let screensaver = self.bus.as_ref().and_then(|bus| {
                self.screensaver
                    .and_then(|path| screensaver_active(bus, path))
            });
            lock_reported(logind, screensaver)
        }

        fn idle_for(&self) -> Option<Duration> {
            let bus = self.bus.as_ref()?;
            match self.idle.as_ref()? {
                Idle::Mutter => mutter_idle(bus),
                Idle::Kde => kde_idle(bus),
            }
        }
    }

    fn logind_session_path(system: &Connection) -> Option<OwnedObjectPath> {
        system
            .call_method(
                Some(LOGIND),
                LOGIND_PATH,
                Some(LOGIND_MANAGER),
                "GetSessionByPID",
                &(std::process::id()),
            )
            .ok()?
            .body()
            .deserialize::<OwnedObjectPath>()
            .ok()
    }

    fn logind_locked_hint(system: &Connection, session: &OwnedObjectPath) -> Option<bool> {
        system
            .call_method(
                Some(LOGIND),
                session.as_str(),
                Some(PROPERTIES),
                "Get",
                &(LOGIND_SESSION, "LockedHint"),
            )
            .ok()?
            .body()
            .deserialize::<zbus::zvariant::Value>()
            .ok()
            .and_then(|value| bool::try_from(value).ok())
    }

    fn screensaver_path(bus: &Connection) -> Option<&'static str> {
        [SCREENSAVER_PATH, KDE_SCREENSAVER_PATH]
            .into_iter()
            .find(|path| screensaver_active(bus, path).is_some())
    }

    fn screensaver_active(bus: &Connection, path: &str) -> Option<bool> {
        bus.call_method(Some(SCREENSAVER), path, Some(SCREENSAVER), "GetActive", &())
            .ok()?
            .body()
            .deserialize::<bool>()
            .ok()
    }

    pub(super) fn lock_reported(logind: Option<bool>, screensaver: Option<bool>) -> bool {
        logind == Some(true) || screensaver == Some(true)
    }

    fn mutter_idle(bus: &Connection) -> Option<Duration> {
        bus.call_method(Some(MUTTER), MUTTER_PATH, Some(MUTTER), "GetIdletime", &())
            .ok()?
            .body()
            .deserialize::<u64>()
            .ok()
            .map(Duration::from_millis)
    }

    fn kde_idle(bus: &Connection) -> Option<Duration> {
        bus.call_method(
            Some(SCREENSAVER),
            KDE_SCREENSAVER_PATH,
            Some(SCREENSAVER),
            "GetSessionIdleTime",
            &(),
        )
        .ok()?
        .body()
        .deserialize::<u32>()
        .ok()
        .map(|seconds| Duration::from_secs(u64::from(seconds)))
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    use super::linux_session;
    use super::monitor::{should_warn, POLL_INTERVAL, WARNING_WINDOW};

    #[test]
    fn a_locked_vault_is_never_warned_about() {
        assert!(!should_warn(Duration::from_secs(5), false));
    }

    #[test]
    fn the_warning_covers_the_last_window_before_the_lock() {
        assert!(should_warn(WARNING_WINDOW, true));
        assert!(should_warn(Duration::from_secs(1), true));
    }

    /// Zero remaining means this poll takes the lock, which needs no warning.
    #[test]
    fn a_lock_already_due_is_not_warned_about() {
        assert!(!should_warn(Duration::ZERO, true));
    }

    #[test]
    fn time_beyond_the_window_is_not_warned_about_yet() {
        assert!(!should_warn(WARNING_WINDOW + POLL_INTERVAL, true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn either_linux_lock_source_can_take_the_lock() {
        assert!(linux_session::lock_reported(Some(true), Some(false)));
        assert!(linux_session::lock_reported(Some(false), Some(true)));
        assert!(linux_session::lock_reported(None, Some(true)));
        assert!(!linux_session::lock_reported(Some(false), None));
    }
}
