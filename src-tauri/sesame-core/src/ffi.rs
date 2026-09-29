//! The C-ABI boundary a future mobile build links against.
//! Every export: validate declared pointer and length pairs, catch panics, and
//! never expose an opened vault as a raw pointer.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::api::OpenedVault;

/// Largest caller-declared input length the C ABI accepts, in bytes.
pub const MAX_FFI_INPUT_BYTES: usize = crate::MAX_VAULT_FILE_BYTES as usize;

/// Most vault handles the C ABI keeps open at once.
pub const MAX_FFI_OPEN_HANDLES: usize = 32;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Ok = 0,
    InvalidArgument = 1,
    InvalidHandle = 2,
    OperationFailed = 3,
    /// A caught panic; reaching it from a real caller is a bug, but it fails safely.
    InternalPanic = 4,
    /// The open-handle table is full; close a vault before opening another.
    HandleLimitReached = 5,
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

fn register(opened: OpenedVault) -> Result<u64, ErrorCode> {
    // Recover poisoned locks so one panicked caller does not leak every future handle operation.
    let mut table = handles()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if table.len() >= MAX_FFI_OPEN_HANDLES {
        return Err(ErrorCode::HandleLimitReached);
    }
    let id = next_handle_id();
    table.insert(id, opened);
    Ok(id)
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
/// A non-null `bytes` must be valid for reads of `len` bytes. A null `bytes`
/// is accepted only when `len` is 0, and `len` must not exceed
/// [`MAX_FFI_INPUT_BYTES`].
unsafe fn read_slice<'a>(bytes: *const u8, len: usize) -> Option<&'a [u8]> {
    if len > MAX_FFI_INPUT_BYTES {
        return None;
    }
    if bytes.is_null() {
        if len == 0 {
            return Some(&[]);
        }
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
/// A non-null `file_bytes` must be valid for reads of `file_len` bytes, and a
/// non-null `secret` valid for reads of `secret_len` bytes. `out_handle` must
/// be valid for a single `u64` write. A null input pointer with a non-zero
/// length, or any length above [`MAX_FFI_INPUT_BYTES`], is rejected with
/// [`ErrorCode::InvalidArgument`]. `out_handle` is only written when the
/// return value is [`ErrorCode::Ok`].
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
            Ok(opened) => match register(opened) {
                Ok(handle) => {
                    // SAFETY: checked non-null above; the caller's contract guarantees validity.
                    unsafe { *out_handle = handle };
                    ErrorCode::Ok
                }
                Err(code) => code,
            },
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

#[cfg(test)]
mod tests {
    #![cfg_attr(test, allow(clippy::unwrap_used))]

    use super::*;
    use crate::loader::MigrationPlan;
    use crate::types::{CipherBlob, KdfParams, VaultFile, VaultPayload};
    use zeroize::Zeroizing;

    fn fictional_opened_vault() -> OpenedVault {
        OpenedVault {
            key: Zeroizing::new([7_u8; 32]),
            payload: VaultPayload::default(),
            file: VaultFile {
                format_version: crate::VAULT_FORMAT_VERSION,
                kdf: KdfParams {
                    algorithm: "argon2id".into(),
                    salt: "ZmljdGlvbmFsIHNhbHQ".into(),
                    memory_kib: 8,
                    iterations: 1,
                    parallelism: 1,
                },
                key_wrap: CipherBlob {
                    nonce: "ZmljdGlvbmFsIG5vbmNl".into(),
                    ciphertext: "ZmljdGlvbmFsIHdyYXA".into(),
                },
                legacy_device_wrap: None,
                recovery_kdf: None,
                recovery_wrap: None,
                pin_wrap: None,
                hello_wrap: None,
                setup_complete: false,
                payload: CipherBlob {
                    nonce: "ZmljdGlvbmFsIG5vbmNl".into(),
                    ciphertext: "ZmljdGlvbmFsIHBheWxvYWQ".into(),
                },
            },
            migrated: false,
            migration: MigrationPlan {
                source_format: crate::VAULT_FORMAT_VERSION,
                target_format: crate::VAULT_FORMAT_VERSION,
                envelope_changed: false,
                payload_changed: false,
            },
        }
    }

    fn handle_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn oversized_lengths_are_refused() {
        let file = b"fictional vault document";
        let secret = b"fictional master password";
        let mut handle = 0_u64;

        let result = unsafe {
            sesame_core_open_vault(
                file.as_ptr(),
                MAX_FFI_INPUT_BYTES + 1,
                secret.as_ptr(),
                secret.len(),
                &mut handle,
            )
        };
        assert_eq!(result, ErrorCode::InvalidArgument as i32);

        let result = unsafe {
            sesame_core_open_vault(
                file.as_ptr(),
                file.len(),
                secret.as_ptr(),
                MAX_FFI_INPUT_BYTES + 1,
                &mut handle,
            )
        };
        assert_eq!(result, ErrorCode::InvalidArgument as i32);
        assert_eq!(handle, 0);
    }

    #[test]
    fn a_null_pointer_with_a_nonzero_length_is_refused() {
        let file = b"fictional vault document";
        let secret = b"fictional master password";
        let mut handle = 0_u64;

        let result = unsafe {
            sesame_core_open_vault(
                std::ptr::null(),
                1,
                secret.as_ptr(),
                secret.len(),
                &mut handle,
            )
        };
        assert_eq!(result, ErrorCode::InvalidArgument as i32);

        let result = unsafe {
            sesame_core_open_vault(file.as_ptr(), file.len(), std::ptr::null(), 1, &mut handle)
        };
        assert_eq!(result, ErrorCode::InvalidArgument as i32);
        assert_eq!(handle, 0);
    }

    #[test]
    fn zero_length_inputs_are_accepted_and_reach_the_vault_loader() {
        let secret = b"fictional master password";
        let mut handle = 0_u64;

        let result = unsafe {
            sesame_core_open_vault(
                std::ptr::null(),
                0,
                secret.as_ptr(),
                secret.len(),
                &mut handle,
            )
        };
        assert_eq!(result, ErrorCode::OperationFailed as i32);

        let empty: [u8; 0] = [];
        let result = unsafe {
            sesame_core_open_vault(
                empty.as_ptr(),
                0,
                secret.as_ptr(),
                secret.len(),
                &mut handle,
            )
        };
        assert_eq!(result, ErrorCode::OperationFailed as i32);
        assert_eq!(handle, 0);
    }

    #[test]
    fn a_full_handle_table_refuses_and_recovers_after_release() {
        let _guard = handle_test_lock();
        let mut handles = Vec::new();
        loop {
            match register(fictional_opened_vault()) {
                Ok(handle) => handles.push(handle),
                Err(code) => {
                    assert_eq!(code, ErrorCode::HandleLimitReached);
                    break;
                }
            }
        }
        assert_eq!(handles.len(), MAX_FFI_OPEN_HANDLES);

        let released = handles.pop().unwrap();
        assert_eq!(sesame_core_close_vault(released), ErrorCode::Ok as i32);
        assert_eq!(
            sesame_core_close_vault(released),
            ErrorCode::InvalidHandle as i32
        );

        let recovered = register(fictional_opened_vault()).unwrap();
        assert!(recovered > released);
        assert_eq!(sesame_core_close_vault(recovered), ErrorCode::Ok as i32);

        for handle in handles {
            assert_eq!(sesame_core_close_vault(handle), ErrorCode::Ok as i32);
        }
    }

    #[test]
    fn double_release_is_refused() {
        let _guard = handle_test_lock();
        let handle = register(fictional_opened_vault()).unwrap();
        assert_eq!(sesame_core_close_vault(handle), ErrorCode::Ok as i32);
        assert_eq!(
            sesame_core_close_vault(handle),
            ErrorCode::InvalidHandle as i32
        );
    }

    #[test]
    fn unknown_handles_are_refused() {
        let _guard = handle_test_lock();
        let mut count = 0_u64;
        assert_eq!(
            unsafe { sesame_core_entry_count(0, &mut count) },
            ErrorCode::InvalidHandle as i32
        );
        assert_eq!(
            unsafe { sesame_core_entry_count(u64::MAX, &mut count) },
            ErrorCode::InvalidHandle as i32
        );
        assert_eq!(count, 0);
        assert_eq!(sesame_core_close_vault(0), ErrorCode::InvalidHandle as i32);
        assert_eq!(
            sesame_core_close_vault(u64::MAX),
            ErrorCode::InvalidHandle as i32
        );
    }

    #[test]
    fn entry_count_rejects_a_null_output_pointer() {
        assert_eq!(
            unsafe { sesame_core_entry_count(0, std::ptr::null_mut()) },
            ErrorCode::InvalidArgument as i32
        );
    }
}
