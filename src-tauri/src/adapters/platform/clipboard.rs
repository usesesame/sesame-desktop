use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use tauri::{AppHandle, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroize;

use crate::vault::VaultResult;

const MAX_CLIPBOARD_COMPARE_BYTES: usize = 1024 * 1024;

/// Digest of the last copied secret; the webview never gains general clipboard-read permission.
#[derive(Default)]
pub struct ClipboardGuard {
    digest: Mutex<Option<[u8; 32]>>,
    epoch: AtomicU64,
}

fn digest(value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

/// Returns an epoch token; a later clear only acts on the newest copy.
#[tauri::command]
pub fn arm_clipboard_clear(state: State<'_, ClipboardGuard>, mut value: String) -> u64 {
    let computed = digest(&value);
    value.zeroize();
    *state
        .digest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(computed);
    state.epoch.fetch_add(1, Ordering::AcqRel) + 1
}

/// Clears only if the clipboard still holds the value armed at `epoch`.
#[tauri::command]
pub fn clear_clipboard_if_unchanged(
    app: AppHandle,
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
    let mut current = app.clipboard().read_text().unwrap_or_default();
    if current.len() > MAX_CLIPBOARD_COMPARE_BYTES {
        current.zeroize();
        return Ok(());
    }
    let unchanged = digest(&current) == expected;
    current.zeroize();
    if unchanged {
        app.clipboard()
            .write_text(String::new())
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
