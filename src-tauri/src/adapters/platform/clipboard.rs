use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroize;

use crate::vault::VaultResult;

const MAX_CLIPBOARD_COMPARE_BYTES: usize = 1024 * 1024;
const MAX_CLIPBOARD_CLEAR_MS: u64 = 5 * 60 * 1_000;
const CLEAR_ATTEMPTS: usize = 3;
const CLEAR_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Digest of the last copied secret; the webview never gains general clipboard-read permission.
#[derive(Default)]
pub struct ClipboardGuard {
    state: Mutex<ClipboardState>,
    #[cfg(any(windows, target_os = "linux"))]
    clipboard: Mutex<Option<arboard::Clipboard>>,
}

#[derive(Default)]
struct ClipboardState {
    digest: Option<[u8; 32]>,
    epoch: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClipboardAccess {
    Ready,
    #[cfg_attr(not(windows), allow(dead_code))]
    Busy,
    #[cfg_attr(not(windows), allow(dead_code))]
    Unsupported,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ClearOutcome {
    Cleared,
    Skipped,
    Busy,
}

fn digest(value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

fn lock_state(state: &ClipboardGuard) -> MutexGuard<'_, ClipboardState> {
    state
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

trait ClipboardBackend {
    fn read(&self, state: &ClipboardGuard) -> Option<String>;
    fn write(&self, state: &ClipboardGuard, value: &str) -> VaultResult<()>;
    fn access(&self) -> ClipboardAccess;
}

struct SystemClipboard;

impl ClipboardBackend for SystemClipboard {
    fn read(&self, state: &ClipboardGuard) -> Option<String> {
        read_clipboard_text(state)
    }

    fn write(&self, state: &ClipboardGuard, value: &str) -> VaultResult<()> {
        write_secret_text(state, value)
    }

    fn access(&self) -> ClipboardAccess {
        clipboard_access(MAX_CLIPBOARD_COMPARE_BYTES)
    }
}

#[cfg(any(windows, target_os = "linux"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SecretExclusion {
    Monitoring,
    History,
}

#[cfg(any(windows, target_os = "linux"))]
fn secret_exclusion_for(os: &str) -> SecretExclusion {
    if os == "windows" {
        SecretExclusion::Monitoring
    } else {
        SecretExclusion::History
    }
}

#[cfg(windows)]
fn with_exclusion(set: arboard::Set<'_>, exclusion: SecretExclusion) -> arboard::Set<'_> {
    use arboard::SetExtWindows;
    match exclusion {
        SecretExclusion::Monitoring => set.exclude_from_monitoring(),
        SecretExclusion::History => set.exclude_from_history(),
    }
}

#[cfg(target_os = "linux")]
fn with_exclusion(set: arboard::Set<'_>, _exclusion: SecretExclusion) -> arboard::Set<'_> {
    use arboard::SetExtLinux;
    set.exclude_from_history()
}

/// A clipboard manager that honours the secret hint keeps the value out of its
/// history, so the timed clear is not undone by a copy the user cannot see. On
/// Windows the same marker also keeps the value out of Cloud Clipboard sync.
#[cfg(any(windows, target_os = "linux"))]
fn write_secret_text(state: &ClipboardGuard, value: &str) -> VaultResult<()> {
    let mut held = state
        .clipboard
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if held.is_none() {
        *held = Some(
            arboard::Clipboard::new()
                .map_err(|_| "Sesame could not reach the clipboard.".to_string())?,
        );
    }
    let clipboard = held
        .as_mut()
        .ok_or_else(|| "Sesame could not reach the clipboard.".to_string())?;
    with_exclusion(clipboard.set(), secret_exclusion_for(std::env::consts::OS))
        .text(value)
        .map_err(|_| "Sesame could not copy to the clipboard.".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
fn write_secret_text(_state: &ClipboardGuard, _value: &str) -> VaultResult<()> {
    Err("Copying is not available on this operating system.".into())
}

/// Releases the selection this process serves; a dropped owner leaves an empty
/// clipboard on Linux rather than a stale secret.
pub fn release(state: &ClipboardGuard) {
    #[cfg(any(windows, target_os = "linux"))]
    {
        let taken = state
            .clipboard
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(taken);
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    let _ = state;
}

/// Reads through the instance that owns the selection, so the owning process
/// never asks the display server for data it is itself serving.
#[cfg(any(windows, target_os = "linux"))]
fn read_clipboard_text(state: &ClipboardGuard) -> Option<String> {
    state
        .clipboard
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()?
        .get_text()
        .ok()
}

#[cfg(not(any(windows, target_os = "linux")))]
fn read_clipboard_text(_state: &ClipboardGuard) -> Option<String> {
    None
}

fn clear_armed_text<B: ClipboardBackend>(
    state: &ClipboardGuard,
    epoch: Option<u64>,
    backend: &B,
) -> VaultResult<ClearOutcome> {
    let mut armed = lock_state(state);
    if let Some(epoch) = epoch {
        if armed.epoch != epoch {
            return Ok(ClearOutcome::Skipped);
        }
    }
    let Some(expected) = armed.digest else {
        return Ok(ClearOutcome::Skipped);
    };
    match backend.access() {
        ClipboardAccess::Busy => return Ok(ClearOutcome::Busy),
        ClipboardAccess::Unsupported => return Ok(ClearOutcome::Skipped),
        ClipboardAccess::Ready => {}
    }
    let mut current = backend.read(state).unwrap_or_default();
    if current.len() > MAX_CLIPBOARD_COMPARE_BYTES {
        current.zeroize();
        return Ok(ClearOutcome::Skipped);
    }
    let unchanged = digest(&current) == expected;
    current.zeroize();
    if !unchanged {
        return Ok(ClearOutcome::Skipped);
    }
    backend.write(state, "")?;
    armed.digest = None;
    Ok(ClearOutcome::Cleared)
}

fn clear_armed_with_retry<B: ClipboardBackend>(
    state: &ClipboardGuard,
    epoch: Option<u64>,
    backend: &B,
    attempts: usize,
    retry_delay: Duration,
) -> VaultResult<bool> {
    for attempt in 1..=attempts {
        match clear_armed_text(state, epoch, backend)? {
            ClearOutcome::Cleared => return Ok(true),
            ClearOutcome::Skipped => return Ok(false),
            ClearOutcome::Busy => {
                if attempt < attempts {
                    std::thread::sleep(retry_delay);
                }
            }
        }
    }
    Ok(false)
}

fn clear_armed_clipboard_from(app: &AppHandle, epoch: Option<u64>) -> VaultResult<()> {
    let guard = match app.try_state::<ClipboardGuard>() {
        Some(guard) => guard,
        None => return Ok(()),
    };
    clear_armed_with_retry(
        &guard,
        epoch,
        &SystemClipboard,
        CLEAR_ATTEMPTS,
        CLEAR_RETRY_DELAY,
    )?;
    Ok(())
}

pub fn clear_armed_clipboard(app: &AppHandle) -> VaultResult<()> {
    clear_armed_clipboard_from(app, None)
}

fn arm_secret<B: ClipboardBackend>(
    state: &ClipboardGuard,
    backend: &B,
    value: &str,
) -> VaultResult<u64> {
    let computed = digest(value);
    let mut armed = lock_state(state);
    backend.write(state, value)?;
    armed.epoch = armed.epoch.wrapping_add(1);
    armed.digest = Some(computed);
    Ok(armed.epoch)
}

fn bounded_clear_after_ms(clear_after_ms: u64) -> u64 {
    clear_after_ms.min(MAX_CLIPBOARD_CLEAR_MS)
}

/// Copies a vault secret and arms the clear in one step, so the value crosses
/// the process boundary once.
#[tauri::command]
pub fn copy_secret(
    app: AppHandle,
    state: State<'_, ClipboardGuard>,
    mut value: String,
    clear_after_ms: Option<u64>,
) -> VaultResult<u64> {
    let written = arm_secret(&state, &SystemClipboard, &value);
    value.zeroize();
    let epoch = written?;
    if let Some(clear_after_ms) = clear_after_ms {
        let clear_after_ms = bounded_clear_after_ms(clear_after_ms);
        let _ = std::thread::Builder::new().spawn(move || {
            std::thread::sleep(Duration::from_millis(clear_after_ms));
            let _ = clear_armed_clipboard_from(&app, Some(epoch));
        });
    }
    Ok(epoch)
}

/// Clears only if the clipboard still holds the value armed at `epoch`.
#[tauri::command]
pub fn clear_clipboard_if_unchanged(
    state: State<'_, ClipboardGuard>,
    epoch: u64,
) -> VaultResult<()> {
    clear_armed_with_retry(
        &state,
        Some(epoch),
        &SystemClipboard,
        CLEAR_ATTEMPTS,
        CLEAR_RETRY_DELAY,
    )?;
    Ok(())
}

#[cfg(windows)]
fn clipboard_access(max_bytes: usize) -> ClipboardAccess {
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::GlobalSize;
    const CF_UNICODETEXT: u32 = 13;

    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
            return ClipboardAccess::Ready;
        }
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return ClipboardAccess::Busy;
        }
        let handle = GetClipboardData(CF_UNICODETEXT);
        let size = if handle.is_null() {
            0
        } else {
            GlobalSize(handle as _)
        };
        let _ = CloseClipboard();
        if size > 0 && size <= max_bytes {
            ClipboardAccess::Ready
        } else {
            ClipboardAccess::Unsupported
        }
    }
}

#[cfg(not(windows))]
fn clipboard_access(_max_bytes: usize) -> ClipboardAccess {
    ClipboardAccess::Ready
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};

    fn armed_digest(state: &ClipboardGuard) -> Option<[u8; 32]> {
        lock_state(state).digest
    }

    type ReadHook = Box<dyn Fn() + Send + Sync>;

    struct FakeClipboard {
        text: Mutex<Option<String>>,
        writable: bool,
        busy_reads: AtomicUsize,
        on_read: Mutex<Option<ReadHook>>,
        read_wait: Mutex<Option<mpsc::Receiver<()>>>,
    }

    impl FakeClipboard {
        fn holding(value: &str) -> FakeClipboard {
            FakeClipboard {
                text: Mutex::new(Some(value.to_string())),
                writable: true,
                busy_reads: AtomicUsize::new(0),
                on_read: Mutex::new(None),
                read_wait: Mutex::new(None),
            }
        }

        fn read_only(value: &str) -> FakeClipboard {
            FakeClipboard {
                text: Mutex::new(Some(value.to_string())),
                writable: false,
                busy_reads: AtomicUsize::new(0),
                on_read: Mutex::new(None),
                read_wait: Mutex::new(None),
            }
        }

        fn busy_for(value: &str, reads: usize) -> FakeClipboard {
            FakeClipboard {
                text: Mutex::new(Some(value.to_string())),
                writable: true,
                busy_reads: AtomicUsize::new(reads),
                on_read: Mutex::new(None),
                read_wait: Mutex::new(None),
            }
        }

        fn text(&self) -> Option<String> {
            self.text
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn busy_reads(&self) -> usize {
            self.busy_reads.load(Ordering::Acquire)
        }
    }

    impl ClipboardBackend for FakeClipboard {
        fn read(&self, _state: &ClipboardGuard) -> Option<String> {
            let snapshot = self.text();
            let hook = self
                .on_read
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(hook) = hook {
                hook();
            }
            let wait = self
                .read_wait
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(wait) = wait {
                let _ = wait.recv_timeout(Duration::from_secs(1));
            }
            snapshot
        }

        fn write(&self, _state: &ClipboardGuard, value: &str) -> VaultResult<()> {
            if !self.writable {
                return Err("The test clipboard is not writable.".into());
            }
            *self
                .text
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(value.to_string());
            Ok(())
        }

        fn access(&self) -> ClipboardAccess {
            if self.busy_reads() == 0 {
                ClipboardAccess::Ready
            } else {
                self.busy_reads.fetch_sub(1, Ordering::AcqRel);
                ClipboardAccess::Busy
            }
        }
    }

    fn armed(value: &str, epoch: u64) -> ClipboardGuard {
        let guard = ClipboardGuard::default();
        {
            let mut state = lock_state(&guard);
            state.digest = Some(digest(value));
            state.epoch = epoch;
        }
        guard
    }

    #[test]
    fn the_lock_path_clears_an_armed_secret() {
        let guard = armed("fictional-armed-secret", 4);
        let clipboard = FakeClipboard::holding("fictional-armed-secret");

        assert_eq!(
            clear_armed_text(&guard, None, &clipboard).unwrap(),
            ClearOutcome::Cleared
        );

        assert_eq!(clipboard.text().as_deref(), Some(""));
        assert_eq!(armed_digest(&guard), None);
    }

    #[test]
    fn the_lock_path_keeps_text_the_user_copied_elsewhere() {
        let guard = armed("fictional-armed-secret", 4);
        let clipboard = FakeClipboard::holding("fictional-user-notes");

        assert_eq!(
            clear_armed_text(&guard, None, &clipboard).unwrap(),
            ClearOutcome::Skipped
        );

        assert_eq!(clipboard.text().as_deref(), Some("fictional-user-notes"));
        assert!(armed_digest(&guard).is_some());
    }

    #[test]
    fn an_older_timer_never_clears_a_newer_secret() {
        let guard = armed("fictional-newer-secret", 7);
        let clipboard = FakeClipboard::holding("fictional-newer-secret");

        assert_eq!(
            clear_armed_text(&guard, Some(6), &clipboard).unwrap(),
            ClearOutcome::Skipped
        );

        assert_eq!(clipboard.text().as_deref(), Some("fictional-newer-secret"));
        assert!(armed_digest(&guard).is_some());
    }

    #[test]
    fn the_current_timer_clears_the_secret_it_armed() {
        let guard = armed("fictional-timed-secret", 7);
        let clipboard = FakeClipboard::holding("fictional-timed-secret");

        assert_eq!(
            clear_armed_text(&guard, Some(7), &clipboard).unwrap(),
            ClearOutcome::Cleared
        );

        assert_eq!(clipboard.text().as_deref(), Some(""));
        assert_eq!(armed_digest(&guard), None);
    }

    #[test]
    fn a_timer_keeps_a_value_the_user_replaced() {
        let guard = armed("fictional-timed-secret", 7);
        let clipboard = FakeClipboard::holding("fictional-replacement");

        assert_eq!(
            clear_armed_text(&guard, Some(7), &clipboard).unwrap(),
            ClearOutcome::Skipped
        );

        assert_eq!(clipboard.text().as_deref(), Some("fictional-replacement"));
        assert!(armed_digest(&guard).is_some());
    }

    #[test]
    fn a_failed_clear_keeps_the_secret_armed() {
        let guard = armed("fictional-armed-secret", 4);
        let clipboard = FakeClipboard::read_only("fictional-armed-secret");

        assert!(clear_armed_text(&guard, None, &clipboard).is_err());

        assert_eq!(clipboard.text().as_deref(), Some("fictional-armed-secret"));
        assert!(armed_digest(&guard).is_some());
    }

    #[test]
    fn copying_twice_clears_only_the_newer_secret() {
        let guard = ClipboardGuard::default();
        let clipboard = FakeClipboard::holding("");
        let first = arm_secret(&guard, &clipboard, "fictional-first-secret").unwrap();
        let second = arm_secret(&guard, &clipboard, "fictional-second-secret").unwrap();
        assert_ne!(first, second);

        assert_eq!(
            clear_armed_text(&guard, Some(first), &clipboard).unwrap(),
            ClearOutcome::Skipped
        );
        assert_eq!(clipboard.text().as_deref(), Some("fictional-second-secret"));

        assert_eq!(
            clear_armed_text(&guard, Some(second), &clipboard).unwrap(),
            ClearOutcome::Cleared
        );
        assert_eq!(clipboard.text().as_deref(), Some(""));
        assert_eq!(armed_digest(&guard), None);
    }

    #[test]
    fn a_concurrent_arm_survives_an_in_flight_clear() {
        let guard = Arc::new(armed("fictional-older-secret", 4));
        let clipboard = Arc::new(FakeClipboard::holding("fictional-older-secret"));
        let newer_epoch = Arc::new(Mutex::new(None));
        let arm_handle = Arc::new(Mutex::new(None));
        let (arm_done_tx, arm_done_rx) = mpsc::channel();

        {
            let hook_clipboard = Arc::clone(&clipboard);
            let hook_guard = Arc::clone(&guard);
            let hook_epoch = Arc::clone(&newer_epoch);
            let hook_handle = Arc::clone(&arm_handle);
            *clipboard
                .on_read
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(move || {
                let arm_guard = Arc::clone(&hook_guard);
                let arm_clipboard = Arc::clone(&hook_clipboard);
                let arm_epoch = Arc::clone(&hook_epoch);
                let sender = arm_done_tx.clone();
                let handle = std::thread::spawn(move || {
                    let epoch =
                        arm_secret(&arm_guard, &*arm_clipboard, "fictional-newer-secret").unwrap();
                    *arm_epoch
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(epoch);
                    let _ = sender.send(());
                });
                *hook_handle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
            }));
        }
        *clipboard
            .read_wait
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(arm_done_rx);

        let clear_guard = Arc::clone(&guard);
        let clear_clipboard = Arc::clone(&clipboard);
        let clear_handle = std::thread::spawn(move || {
            clear_armed_text(&clear_guard, Some(4), &*clear_clipboard).unwrap()
        });

        assert_eq!(clear_handle.join().unwrap(), ClearOutcome::Cleared);
        arm_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .unwrap()
            .join()
            .unwrap();

        let newer = newer_epoch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unwrap();
        assert_eq!(clipboard.text().as_deref(), Some("fictional-newer-secret"));
        assert_eq!(armed_digest(&guard), Some(digest("fictional-newer-secret")));
        assert_eq!(lock_state(&guard).epoch, newer);

        assert_eq!(
            clear_armed_text(&guard, Some(newer), &*clipboard).unwrap(),
            ClearOutcome::Cleared
        );
        assert_eq!(clipboard.text().as_deref(), Some(""));
        assert_eq!(armed_digest(&guard), None);
    }

    #[test]
    fn the_lock_path_retries_a_busy_clipboard() {
        let guard = armed("fictional-armed-secret", 4);
        let clipboard = FakeClipboard::busy_for("fictional-armed-secret", 2);

        assert!(
            clear_armed_with_retry(&guard, None, &clipboard, CLEAR_ATTEMPTS, Duration::ZERO)
                .unwrap()
        );

        assert_eq!(clipboard.busy_reads(), 0);
        assert_eq!(clipboard.text().as_deref(), Some(""));
        assert_eq!(armed_digest(&guard), None);
    }

    #[test]
    fn the_lock_path_stops_retrying_a_still_busy_clipboard() {
        let guard = armed("fictional-armed-secret", 4);
        let clipboard = FakeClipboard::busy_for("fictional-armed-secret", 10);

        assert!(
            !clear_armed_with_retry(&guard, None, &clipboard, CLEAR_ATTEMPTS, Duration::ZERO)
                .unwrap()
        );

        assert_eq!(clipboard.busy_reads(), 10 - CLEAR_ATTEMPTS);
        assert_eq!(clipboard.text().as_deref(), Some("fictional-armed-secret"));
        assert!(armed_digest(&guard).is_some());
    }

    #[test]
    fn the_clear_delay_is_bounded() {
        assert_eq!(bounded_clear_after_ms(1_000), 1_000);
        assert_eq!(bounded_clear_after_ms(u64::MAX), MAX_CLIPBOARD_CLEAR_MS);
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn the_exclusion_choice_follows_the_operating_system() {
        assert_eq!(secret_exclusion_for("windows"), SecretExclusion::Monitoring);
        assert_eq!(secret_exclusion_for("linux"), SecretExclusion::History);
        assert_eq!(secret_exclusion_for("macos"), SecretExclusion::History);
        assert_eq!(secret_exclusion_for(""), SecretExclusion::History);
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn this_system_picks_the_exclusion_its_clipboard_supports() {
        let expected = if cfg!(windows) {
            SecretExclusion::Monitoring
        } else {
            SecretExclusion::History
        };
        assert_eq!(secret_exclusion_for(std::env::consts::OS), expected);
    }
}

#[cfg(all(test, windows))]
mod windows_clipboard_formats {
    use super::*;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EnumClipboardFormats, GetClipboardFormatNameW, OpenClipboard,
    };

    const MONITORING_FORMAT: &str = "ExcludeClipboardContentFromMonitorProcessing";

    fn registered_format_names() -> Vec<String> {
        unsafe {
            let mut opened = false;
            for _ in 0..40 {
                if OpenClipboard(std::ptr::null_mut()) != 0 {
                    opened = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(opened, "the clipboard could not be opened for reading");
            let mut names = Vec::new();
            let mut format = 0;
            loop {
                format = EnumClipboardFormats(format);
                if format == 0 {
                    break;
                }
                let mut buffer = [0u16; 256];
                let length =
                    GetClipboardFormatNameW(format, buffer.as_mut_ptr(), buffer.len() as i32);
                if length > 0 {
                    names.push(String::from_utf16_lossy(&buffer[..length as usize]));
                }
            }
            let _ = CloseClipboard();
            names
        }
    }

    #[test]
    #[ignore = "writes to the user clipboard"]
    fn a_secret_copy_and_its_clear_both_carry_the_monitoring_exclusion() {
        let guard = ClipboardGuard::default();

        arm_secret(&guard, &SystemClipboard, "fictional-clipboard-secret").unwrap();

        assert_eq!(
            SystemClipboard.read(&guard).as_deref(),
            Some("fictional-clipboard-secret")
        );
        assert!(registered_format_names()
            .iter()
            .any(|name| name == MONITORING_FORMAT));

        assert_eq!(
            clear_armed_text(&guard, None, &SystemClipboard).unwrap(),
            ClearOutcome::Cleared
        );

        assert_eq!(SystemClipboard.read(&guard).unwrap_or_default(), "");
        assert!(registered_format_names()
            .iter()
            .any(|name| name == MONITORING_FORMAT));
        release(&guard);
    }
}
