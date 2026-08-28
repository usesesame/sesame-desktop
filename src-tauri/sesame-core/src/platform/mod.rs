//! Device protection ties vault material to one device, and the file helpers
//! keep the vault private. Each operating system module owns its own
//! mechanics, including wallet start-up, so callers only ever see the three
//! protection functions.

#[cfg(not(any(windows, target_os = "linux")))]
use crate::VaultResult;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{device_protection_available, protect_for_device, unprotect_for_device};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{device_protection_available, protect_for_device, unprotect_for_device};

mod fs;
pub use fs::{
    copy_private_file, create_private_dir, open_private_file, replace_file, securely_delete,
};

#[cfg(not(any(windows, target_os = "linux")))]
pub fn device_protection_available() -> bool {
    false
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn protect_for_device(_data: &[u8]) -> VaultResult<Vec<u8>> {
    Err("Device protection is not available on this operating system.".into())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn unprotect_for_device(_data: &[u8]) -> VaultResult<Vec<u8>> {
    Err("Device protection is not available on this operating system.".into())
}
