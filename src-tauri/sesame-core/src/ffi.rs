//! The C-ABI boundary a future mobile build links against.
//! Every export: null-check raw pointers, catch panics, and never expose an opened vault as a raw pointer.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::api::OpenedVault;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Ok = 0,
    InvalidArgument = 1,
    InvalidHandle = 2,
    OperationFailed = 3,
    /// A caught panic; reaching it from a real caller is a bug, but it fails safely.
    InternalPanic = 4,
}

fn handles() -> &'static Mutex<HashMap<u64, OpenedVault>> {
    static HANDLES: OnceLock<Mutex<HashMap<u64, OpenedVault>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn register(opened: OpenedVault) -> u64 {
    let id = next_handle_id();
    // Recover poisoned locks so one panicked caller does not leak every future handle operation.
    let mut table = handles()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    table.insert(id, opened);
    id
}

/// Removes and returns the entry; dropping it zeroizes the payload and key.
fn take(handle: u64) -> Option<OpenedVault> {
    let mut table = handles()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    table.remove(&handle)
}

fn with_handle<T>(handle: u64, f: impl FnOnce(&OpenedVault) -> T) -> Option<T> {
    let table = handles()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    table.get(&handle).map(f)
}

/// # Safety
/// `bytes` must be valid for reads of `len` bytes, or `len` must be 0.
unsafe fn read_slice<'a>(bytes: *const u8, len: usize) -> Option<&'a [u8]> {
    if bytes.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(bytes, len))
}

#[no_mangle]
pub extern "C" fn sesame_core_api_version() -> u32 {
    crate::CORE_API_VERSION
}

/// Opens a vault from raw bytes; `out_handle` is written only on success.
///
/// # Safety
/// `file_bytes` must be valid for reads of `file_len` bytes, `secret` valid
/// for reads of `secret_len` bytes, and `out_handle` valid for a single
/// `u64` write. All three must be non-null; `file_len`/`secret_len` may be
/// 0. `out_handle` is only written when the return value is
/// [`ErrorCode::Ok`].
#[no_mangle]
pub unsafe extern "C" fn sesame_core_open_vault(
    file_bytes: *const u8,
    file_len: usize,
    secret: *const u8,
    secret_len: usize,
    out_handle: *mut u64,
) -> i32 {
    let outcome = std::panic::catch_unwind(|| {
        if out_handle.is_null() {
            return ErrorCode::InvalidArgument;
        }
        let Some(file_bytes) = read_slice(file_bytes, file_len) else {
            return ErrorCode::InvalidArgument;
        };
        let Some(secret_bytes) = read_slice(secret, secret_len) else {
            return ErrorCode::InvalidArgument;
        };
        let Ok(secret_str) = std::str::from_utf8(secret_bytes) else {
            return ErrorCode::InvalidArgument;
        };
        match crate::api::open_vault_bytes(file_bytes, secret_str) {
            Ok(opened) => {
                let handle = register(opened);
                // SAFETY: checked non-null above; the caller's contract guarantees validity.
                unsafe { *out_handle = handle };
                ErrorCode::Ok
            }
            Err(_) => ErrorCode::OperationFailed,
        }
    });
    outcome.unwrap_or(ErrorCode::InternalPanic) as i32
}

/// Closes a handle, zeroizing its contents; a stale or double close is refused.
#[no_mangle]
pub extern "C" fn sesame_core_close_vault(handle: u64) -> i32 {
    let outcome = std::panic::catch_unwind(|| match take(handle) {
        Some(opened) => {
            drop(opened);
            ErrorCode::Ok
        }
        None => ErrorCode::InvalidHandle,
    });
    outcome.unwrap_or(ErrorCode::InternalPanic) as i32
}

/// Minimal read proving a handle still resolves to real data.
///
/// # Safety
/// `out_count` must be valid for a single `u64` write when this returns
/// [`ErrorCode::Ok`].
#[no_mangle]
pub unsafe extern "C" fn sesame_core_entry_count(handle: u64, out_count: *mut u64) -> i32 {
    let outcome = std::panic::catch_unwind(|| {
        if out_count.is_null() {
            return ErrorCode::InvalidArgument;
        }
        match with_handle(handle, |opened| opened.payload.entries.len() as u64) {
            Some(count) => {
                // SAFETY: checked non-null above; caller's contract covers validity.
                unsafe { *out_count = count };
                ErrorCode::Ok
            }
            None => ErrorCode::InvalidHandle,
        }
    });
    outcome.unwrap_or(ErrorCode::InternalPanic) as i32
}
