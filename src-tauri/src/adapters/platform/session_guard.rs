//! Clears the unlocked vault when the desktop session locks or the user is inactive.
//! Runs on system input independent of the webview: throttling or a suspended renderer cannot keep a vault open.

mod activity {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    #[cfg(any(windows, target_os = "linux"))]
    use std::time::Duration;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();
    static LAST_MILLIS: AtomicU64 = AtomicU64::new(0);

    fn elapsed_millis() -> u64 {
        u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub fn record() {
        LAST_MILLIS.store(elapsed_millis(), Ordering::Release);
    }

    #[cfg(any(windows, target_os = "linux"))]
    pub fn idle_for() -> Duration {
        Duration::from_millis(elapsed_millis().saturating_sub(LAST_MILLIS.load(Ordering::Acquire)))
    }
}

/// Input in the Sesame window, reported by the interface. It stands in for the desktop's idle time only where the desktop reports none.
pub fn record_activity() {
    activity::record();
}

#[cfg(any(windows, target_os = "linux"))]
mod monitor {
    use std::time::{Duration, Instant, SystemTime};

    use tauri::{AppHandle, Emitter, Manager};

    pub(super) const POLL_INTERVAL: Duration = Duration::from_secs(1);
    pub(super) const WARNING_WINDOW: Duration = Duration::from_secs(30);
    pub(super) const REDISCOVER_INTERVAL: Duration = Duration::from_secs(30);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum LockState {
        Locked,
        Unlocked,
        Unknown,
    }

    pub(super) trait SessionMonitor: Send + 'static {
        fn lock_state(&self) -> LockState;
        fn idle_for(&self) -> Option<Duration>;
        fn rediscover(&mut self) {}
    }

    #[derive(Default)]
    pub(super) struct Blindness {
        seen_signal: bool,
        since: Option<Instant>,
    }

    impl Blindness {
        pub(super) fn observe(
            &mut self,
            lock: LockState,
            idle: Option<Duration>,
            now: Instant,
        ) -> Duration {
            if lock != LockState::Unknown || idle.is_some() {
                self.seen_signal = true;
                self.since = None;
                return Duration::ZERO;
            }
            if !self.seen_signal {
                return Duration::ZERO;
            }
            now.duration_since(*self.since.get_or_insert(now))
        }
    }

    pub(super) fn effective_idle(
        reported: Option<Duration>,
        session_open: bool,
        app_idle: Duration,
    ) -> Option<Duration> {
        reported.or_else(|| session_open.then_some(app_idle))
    }

    pub(super) fn run<M: SessionMonitor>(app: AppHandle, mut monitor: M) {
        let mut warning_shown = false;
        let mut was_open = false;
        let mut last_tick = SystemTime::now();
        let mut last_discovery = Instant::now();
        let mut blindness = Blindness::default();
        loop {
            std::thread::sleep(POLL_INTERVAL);
            let now = SystemTime::now();
            let asleep = asleep_for(last_tick, now);
            last_tick = now;
            if last_discovery.elapsed() >= REDISCOVER_INTERVAL {
                monitor.rediscover();
                last_discovery = Instant::now();
            }
            let lock = monitor.lock_state();
            let reported_idle = monitor.idle_for();
            let blind_for = blindness.observe(lock, reported_idle, Instant::now());
            let open = session_is_open(&app);
            if open && !was_open {
                super::activity::record();
            }
            was_open = open;
            let idle = effective_idle(reported_idle, open, super::activity::idle_for());
            let timeout = Duration::from_secs(
                app.state::<crate::vault::VaultState>()
                    .auto_lock_minutes()
                    .saturating_mul(60),
            );
            if lock == LockState::Locked
                || past_delay(asleep, timeout)
                || past_delay(blind_for, timeout)
            {
                crate::desktop_shell::lock_vault_if_unlocked(&app);
                warning_shown = clear_warning(&app, warning_shown);
                continue;
            }
            match idle {
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
    }

    pub(super) fn asleep_for(previous: SystemTime, now: SystemTime) -> Duration {
        now.duration_since(previous)
            .unwrap_or_default()
            .saturating_sub(POLL_INTERVAL)
    }

    pub(super) fn past_delay(asleep: Duration, timeout: Duration) -> bool {
        !timeout.is_zero() && asleep >= timeout
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
        session.record_protections();
        std::thread::spawn(move || monitor::run(app, session));
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn start(_app: tauri::AppHandle) {}

pub fn idle_auto_lock_available() -> bool {
    cfg!(any(windows, target_os = "linux"))
}

pub fn system_idle_reporting() -> bool {
    #[cfg(windows)]
    {
        true
    }
    #[cfg(target_os = "linux")]
    {
        linux_session::idle_reporting()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

pub fn screen_lock_monitoring_available() -> bool {
    #[cfg(windows)]
    {
        true
    }
    #[cfg(target_os = "linux")]
    {
        linux_session::screen_lock_reporting()
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
        fn lock_state(&self) -> super::monitor::LockState {
            use windows_sys::Win32::System::StationsAndDesktops::{
                CloseDesktop, OpenInputDesktop, DESKTOP_READOBJECTS,
            };

            let desktop = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
            if desktop.is_null() {
                super::monitor::LockState::Locked
            } else {
                unsafe { CloseDesktop(desktop) };
                super::monitor::LockState::Unlocked
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

/// A probe that cannot tell reports nothing rather than guessing.
#[cfg(target_os = "linux")]
mod linux_session {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use zbus::blocking::Connection;
    use zbus::zvariant::OwnedObjectPath;

    use super::monitor::{LockState, SessionMonitor};

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

    static IDLE_REPORTING: AtomicBool = AtomicBool::new(false);
    static SCREEN_LOCK_REPORTING: AtomicBool = AtomicBool::new(false);

    pub fn idle_reporting() -> bool {
        IDLE_REPORTING.load(Ordering::Acquire)
    }

    pub fn screen_lock_reporting() -> bool {
        SCREEN_LOCK_REPORTING.load(Ordering::Acquire)
    }

    #[derive(Clone, Copy)]
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
        stale: Cell<bool>,
    }

    impl Session {
        pub fn connect() -> Session {
            let system = Connection::system().ok();
            let bus = Connection::session().ok();
            let logind = system.as_ref().and_then(logind_session_path);
            let screensaver = bus.as_ref().and_then(screensaver_path);
            let idle = bus.as_ref().and_then(idle_source);
            Session {
                system,
                bus,
                logind,
                screensaver,
                idle,
                stale: Cell::new(false),
            }
        }

        pub fn record_protections(&self) {
            let _ = self.lock_state();
            let _ = self.idle_for();
        }

        fn needs_rediscovery(&self) -> bool {
            self.stale.get()
                || self.logind.is_none()
                || self.screensaver.is_none()
                || self.idle.is_none()
        }

        fn logind_state(&self) -> Option<bool> {
            let system = self.system.as_ref()?;
            logind_locked_hint(system, self.logind.as_ref()?)
        }

        fn screensaver_state(&self) -> Option<bool> {
            screensaver_active(self.bus.as_ref()?, self.screensaver?)
        }
    }

    impl SessionMonitor for Session {
        fn lock_state(&self) -> LockState {
            let logind = self.logind_state();
            let screensaver = self.screensaver_state();
            let failed = (self.logind.is_some() && logind.is_none())
                || (self.screensaver.is_some() && screensaver.is_none());
            self.stale.set(self.stale.get() || failed);
            SCREEN_LOCK_REPORTING
                .store(logind.is_some() || screensaver.is_some(), Ordering::Release);
            lock_state_from(logind, screensaver)
        }

        fn idle_for(&self) -> Option<Duration> {
            let idle = self
                .bus
                .as_ref()
                .zip(self.idle)
                .and_then(|(bus, idle)| match idle {
                    Idle::Mutter => mutter_idle(bus),
                    Idle::Kde => kde_idle(bus),
                });
            if self.idle.is_some() && idle.is_none() {
                self.stale.set(true);
            }
            IDLE_REPORTING.store(idle.is_some(), Ordering::Release);
            idle
        }

        fn rediscover(&mut self) {
            if !self.needs_rediscovery() {
                return;
            }
            let fresh = Session::connect();
            if fresh.system.is_some() {
                self.system = fresh.system;
            }
            if fresh.bus.is_some() {
                self.bus = fresh.bus;
            }
            if fresh.logind.is_some() {
                self.logind = fresh.logind;
            }
            if fresh.screensaver.is_some() {
                self.screensaver = fresh.screensaver;
            }
            if fresh.idle.is_some() {
                self.idle = fresh.idle;
            }
            self.stale.set(false);
        }
    }

    fn idle_source(bus: &Connection) -> Option<Idle> {
        if mutter_idle(bus).is_some() {
            Some(Idle::Mutter)
        } else if kde_idle(bus).is_some() {
            Some(Idle::Kde)
        } else {
            None
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

    pub(super) fn lock_state_from(logind: Option<bool>, screensaver: Option<bool>) -> LockState {
        if logind == Some(true) || screensaver == Some(true) {
            LockState::Locked
        } else if logind.is_some() || screensaver.is_some() {
            LockState::Unlocked
        } else {
            LockState::Unknown
        }
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
    use super::monitor::{
        asleep_for, effective_idle, past_delay, should_warn, Blindness, LockState, POLL_INTERVAL,
        WARNING_WINDOW,
    };
    use std::time::{Instant, SystemTime};

    #[test]
    fn a_desktop_that_reports_idle_time_is_always_believed() {
        let reported = Some(Duration::from_secs(40));
        assert_eq!(
            effective_idle(reported, true, Duration::from_secs(900)),
            reported
        );
        assert_eq!(
            effective_idle(reported, false, Duration::from_secs(900)),
            reported
        );
    }

    #[test]
    fn a_desktop_without_idle_time_falls_back_to_window_activity_while_unlocked() {
        assert_eq!(
            effective_idle(None, true, Duration::from_secs(61)),
            Some(Duration::from_secs(61))
        );
    }

    #[test]
    fn a_locked_vault_has_no_fallback_idle_time_to_warn_about() {
        assert_eq!(effective_idle(None, false, Duration::from_secs(61)), None);
    }

    #[test]
    fn the_fallback_idle_time_reaches_the_lock_delay_and_resets_on_activity() {
        let timeout = Duration::from_secs(60);
        let idle = effective_idle(None, true, Duration::from_secs(60)).unwrap();
        assert!(idle >= timeout);
        super::record_activity();
        let fresh = effective_idle(None, true, super::activity::idle_for()).unwrap();
        assert!(fresh < Duration::from_secs(5));
        assert!(fresh < timeout);
    }

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

    #[test]
    fn a_sleep_longer_than_the_auto_lock_delay_locks() {
        let before = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let five_minutes = Duration::from_secs(300);
        let asleep = asleep_for(before, before + POLL_INTERVAL + five_minutes);
        assert_eq!(asleep, five_minutes);
        assert!(past_delay(asleep, five_minutes));
        assert!(!past_delay(asleep, five_minutes + Duration::from_secs(1)));
    }

    #[test]
    fn an_ordinary_poll_or_a_clock_set_backwards_is_not_a_sleep() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(asleep_for(now, now + POLL_INTERVAL), Duration::ZERO);
        assert_eq!(
            asleep_for(now, now - Duration::from_secs(3_600)),
            Duration::ZERO
        );
        assert!(!past_delay(Duration::ZERO, Duration::from_secs(60)));
        assert!(!past_delay(Duration::from_secs(600), Duration::ZERO));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn either_linux_lock_source_can_take_the_lock() {
        assert_eq!(
            linux_session::lock_state_from(Some(true), Some(false)),
            LockState::Locked
        );
        assert_eq!(
            linux_session::lock_state_from(Some(false), Some(true)),
            LockState::Locked
        );
        assert_eq!(
            linux_session::lock_state_from(None, Some(true)),
            LockState::Locked
        );
        assert_eq!(
            linux_session::lock_state_from(Some(false), None),
            LockState::Unlocked
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_answering_source_is_unknown_and_never_unlocked() {
        assert_eq!(
            linux_session::lock_state_from(None, None),
            LockState::Unknown
        );
    }

    #[test]
    fn a_session_that_never_reported_anything_is_not_treated_as_blind() {
        let start = Instant::now();
        let mut blindness = Blindness::default();
        assert_eq!(
            blindness.observe(LockState::Unknown, None, start),
            Duration::ZERO
        );
        assert_eq!(
            blindness.observe(LockState::Unknown, None, start + Duration::from_secs(900)),
            Duration::ZERO
        );
    }

    #[test]
    fn losing_every_source_after_one_answered_counts_the_blind_time() {
        let start = Instant::now();
        let mut blindness = Blindness::default();
        blindness.observe(LockState::Unlocked, None, start);
        assert_eq!(
            blindness.observe(LockState::Unknown, None, start + Duration::from_secs(10)),
            Duration::ZERO
        );
        assert_eq!(
            blindness.observe(LockState::Unknown, None, start + Duration::from_secs(70)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn one_answer_ends_the_blind_period() {
        let start = Instant::now();
        let mut blindness = Blindness::default();
        blindness.observe(LockState::Unlocked, None, start);
        blindness.observe(LockState::Unknown, None, start + Duration::from_secs(10));
        blindness.observe(
            LockState::Unknown,
            Some(Duration::from_secs(3)),
            start + Duration::from_secs(40),
        );
        assert_eq!(
            blindness.observe(LockState::Unknown, None, start + Duration::from_secs(50)),
            Duration::ZERO
        );
    }

    #[test]
    fn a_blind_period_locks_once_it_reaches_the_auto_lock_delay() {
        let delay = Duration::from_secs(300);
        assert!(!past_delay(Duration::from_secs(299), delay));
        assert!(past_delay(delay, delay));
        assert!(!past_delay(Duration::from_secs(900), Duration::ZERO));
    }
}
