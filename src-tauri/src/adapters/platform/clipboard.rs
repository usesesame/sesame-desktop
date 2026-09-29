use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroize;

use crate::vault::VaultResult;

const MAX_CLIPBOARD_COMPARE_BYTES: usize = 1024 * 1024;

/// Digest of the last copied secret; the webview never gains general clipboard-read permission.
#[derive(Default)]
pub struct ClipboardGuard {
    digest: Mutex<Option<[u8; 32]>>,
    epoch: AtomicU64,
    #[cfg(any(windows, target_os = "linux"))]
    clipboard: Mutex<Option<arboard::Clipboard>>,
}

fn digest(value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

fn armed_digest(state: &ClipboardGuard) -> Option<[u8; 32]> {
    *state
        .digest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn set_armed_digest(state: &ClipboardGuard, value: Option<[u8; 32]>) {
    *state
        .digest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = value;
}

trait ClipboardBackend {
    fn read(&self, state: &ClipboardGuard) -> Option<String>;
    fn write(&self, state: &ClipboardGuard, value: &str) -> VaultResult<()>;
    fn within_limit(&self) -> bool;
}

struct SystemClipboard;

impl ClipboardBackend for SystemClipboard {
    fn read(&self, state: &ClipboardGuard) -> Option<String> {
        read_clipboard_text(state)
    }

    fn write(&self, state: &ClipboardGuard, value: &str) -> VaultResult<()> {
        write_secret_text(state, value)
    }

    fn within_limit(&self) -> bool {
        clipboard_text_within_limit(MAX_CLIPBOARD_COMPARE_BYTES)
    }
}

/// A clipboard manager that honours the secret hint keeps the value out of its
/// history, so the timed clear is not undone by a copy the user cannot see.
#[cfg(any(windows, target_os = "linux"))]
fn write_secret_text(state: &ClipboardGuard, value: &str) -> VaultResult<()> {
    #[cfg(target_os = "linux")]
    use arboard::SetExtLinux as SetExt;
    #[cfg(windows)]
    use arboard::SetExtWindows as SetExt;

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
    clipboard
        .set()
        .exclude_from_history()
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
) -> VaultResult<bool> {
    if let Some(epoch) = epoch {
        if state.epoch.load(Ordering::Acquire) != epoch {
            return Ok(false);
        }
    }
    let expected = match armed_digest(state) {
        Some(expected) => expected,
        None => return Ok(false),
    };
    if !backend.within_limit() {
        return Ok(false);
    }
    let mut current = backend.read(state).unwrap_or_default();
    if current.len() > MAX_CLIPBOARD_COMPARE_BYTES {
        current.zeroize();
        return Ok(false);
    }
    let unchanged = digest(&current) == expected;
    current.zeroize();
    if !unchanged {
        return Ok(false);
    }
    if let Some(epoch) = epoch {
        if state.epoch.load(Ordering::Acquire) != epoch {
            return Ok(false);
        }
    }
    backend.write(state, "")?;
    let mut armed = state
        .digest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *armed == Some(expected) {
        *armed = None;
    }
    Ok(true)
}

fn clear_armed_clipboard_from(app: &AppHandle, epoch: Option<u64>) -> VaultResult<()> {
    let guard = match app.try_state::<ClipboardGuard>() {
        Some(guard) => guard,
        None => return Ok(()),
    };
    clear_armed_text(&guard, epoch, &SystemClipboard)?;
    Ok(())
}

pub fn clear_armed_clipboard(app: &AppHandle) -> VaultResult<()> {
    clear_armed_clipboard_from(app, None)
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
    let written = write_secret_text(&state, &value);
    let computed = digest(&value);
    value.zeroize();
    written?;
    set_armed_digest(&state, Some(computed));
    let epoch = state.epoch.fetch_add(1, Ordering::AcqRel) + 1;
    if let Some(clear_after_ms) = clear_after_ms {
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
    clear_armed_text(&state, Some(epoch), &SystemClipboard)?;
    Ok(())
}

#[cfg(windows)]
fn clipboard_text_within_limit(max_bytes: usize) -> bool {
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::GlobalSize;
    const CF_UNICODETEXT: u32 = 13;

    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
            return true;
        }
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return false;
        }
        let handle = GetClipboardData(CF_UNICODETEXT);
        let size = if handle.is_null() {
            0
        } else {
            GlobalSize(handle as _)
        };
        let _ = CloseClipboard();
        size > 0 && size <= max_bytes
    }
}

#[cfg(not(windows))]
fn clipboard_text_within_limit(_max_bytes: usize) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeClipboard {
        text: Mutex<Option<String>>,
        writable: bool,
    }

    impl FakeClipboard {
        fn holding(value: &str) -> FakeClipboard {
            FakeClipboard {
                text: Mutex::new(Some(value.to_string())),
                writable: true,
            }
        }

        fn read_only(value: &str) -> FakeClipboard {
            FakeClipboard {
                text: Mutex::new(Some(value.to_string())),
                writable: false,
            }
        }

        fn text(&self) -> Option<String> {
            self.text
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl ClipboardBackend for FakeClipboard {
        fn read(&self, _state: &ClipboardGuard) -> Option<String> {
            self.text()
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

        fn within_limit(&self) -> bool {
            true
        }
    }

    fn armed(value: &str, epoch: u64) -> ClipboardGuard {
        let guard = ClipboardGuard::default();
        set_armed_digest(&guard, Some(digest(value)));
        guard.epoch.store(epoch, Ordering::Release);
        guard
    }

    #[test]
    fn the_lock_path_clears_an_armed_secret() {
        let guard = armed("fictional-armed-secret", 4);
        let clipboard = FakeClipboard::holding("fictional-armed-secret");

        assert!(clear_armed_text(&guard, None, &clipboard).unwrap());

        assert_eq!(clipboard.text().as_deref(), Some(""));
        assert_eq!(armed_digest(&guard), None);
    }

    #[test]
    fn the_lock_path_keeps_text_the_user_copied_elsewhere() {
        let guard = armed("fictional-armed-secret", 4);
        let clipboard = FakeClipboard::holding("fictional-user-notes");

        assert!(!clear_armed_text(&guard, None, &clipboard).unwrap());

        assert_eq!(clipboard.text().as_deref(), Some("fictional-user-notes"));
        assert!(armed_digest(&guard).is_some());
    }

    #[test]
    fn an_older_timer_never_clears_a_newer_secret() {
        let guard = armed("fictional-newer-secret", 7);
        let clipboard = FakeClipboard::holding("fictional-newer-secret");

        assert!(!clear_armed_text(&guard, Some(6), &clipboard).unwrap());

        assert_eq!(clipboard.text().as_deref(), Some("fictional-newer-secret"));
        assert!(armed_digest(&guard).is_some());
    }

    #[test]
    fn the_current_timer_clears_the_secret_it_armed() {
        let guard = armed("fictional-timed-secret", 7);
        let clipboard = FakeClipboard::holding("fictional-timed-secret");

        assert!(clear_armed_text(&guard, Some(7), &clipboard).unwrap());

        assert_eq!(clipboard.text().as_deref(), Some(""));
        assert_eq!(armed_digest(&guard), None);
    }

    #[test]
    fn a_timer_keeps_a_value_the_user_replaced() {
        let guard = armed("fictional-timed-secret", 7);
        let clipboard = FakeClipboard::holding("fictional-replacement");

        assert!(!clear_armed_text(&guard, Some(7), &clipboard).unwrap());

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
}
