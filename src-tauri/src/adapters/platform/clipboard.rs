use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use tauri::State;
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

/// Copies a vault secret and arms the clear in one step, so the value crosses
/// the process boundary once.
#[tauri::command]
pub fn copy_secret(state: State<'_, ClipboardGuard>, mut value: String) -> VaultResult<u64> {
    let written = write_secret_text(&state, &value);
    let computed = digest(&value);
    value.zeroize();
    written?;
    *state
        .digest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(computed);
    Ok(state.epoch.fetch_add(1, Ordering::AcqRel) + 1)
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

/// Clears only if the clipboard still holds the value armed at `epoch`.
#[tauri::command]
pub fn clear_clipboard_if_unchanged(
    state: State<'_, ClipboardGuard>,
    epoch: u64,
) -> VaultResult<()> {
    if state.epoch.load(Ordering::Acquire) != epoch {
        return Ok(());
    }
    let expected = match *state
        .digest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        Some(expected) => expected,
        None => return Ok(()),
    };
    if !clipboard_text_within_limit(MAX_CLIPBOARD_COMPARE_BYTES) {
        return Ok(());
    }
    let mut current = read_clipboard_text(&state).unwrap_or_default();
    if current.len() > MAX_CLIPBOARD_COMPARE_BYTES {
        current.zeroize();
        return Ok(());
    }
    let unchanged = digest(&current) == expected;
    current.zeroize();
    if unchanged {
        write_secret_text(&state, "")
            .map_err(|_| "Sesame could not clear the clipboard.".to_string())?;
        *state
            .digest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
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
