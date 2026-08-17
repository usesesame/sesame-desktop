//! AppHandle-to-path resolution for vault and PIN-throttle files, plus re-exports of `sesame-core` persistence.
//! This crate decides where files live, never what they look like.

pub use sesame_core::storage::*;

use std::path::PathBuf;

use sesame_core::throttle::{PersistedPinThrottle, PinAttemptGuard};
use sesame_core::VaultResult;
use tauri::{AppHandle, Manager};

pub fn vault_path(app: &AppHandle) -> VaultResult<PathBuf> {
    #[cfg(feature = "wdio")]
    if let Some(root) = std::env::args().find_map(|argument| {
        argument
            .strip_prefix("--sesame-e2e-root=")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }) {
        return Ok(root.join("vault.sesame"));
    }
    let mut path = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
    path.push("vault.sesame");
    Ok(path)
}

/// Records only PIN rate-limit state, never a PIN, password, key, or kit.
pub fn pin_throttle_path(app: &AppHandle) -> VaultResult<PathBuf> {
    let mut path = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
    path.push(sesame_core::storage::PIN_THROTTLE_FILE);
    Ok(path)
}

pub fn read_pin_throttle_state(app: &AppHandle) -> VaultResult<Option<PersistedPinThrottle>> {
    sesame_core::storage::read_pin_throttle_state_at(&pin_throttle_path(app)?)
}

pub fn write_pin_throttle_state(app: &AppHandle, guard: &PinAttemptGuard) -> VaultResult<()> {
    sesame_core::storage::write_pin_throttle_state_at(&pin_throttle_path(app)?, guard)
}

pub fn clear_pin_throttle_state(app: &AppHandle) -> VaultResult<()> {
    sesame_core::storage::clear_pin_throttle_state_at(&pin_throttle_path(app)?)
}
