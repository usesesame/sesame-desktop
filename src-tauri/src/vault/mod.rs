//! The Windows desktop half of the vault boundary; platform-agnostic behavior lives in `sesame-core`.
//! What stays local: recovery-health state, AppHandle-to-path resolution, and the compatibility re-exports below.

pub mod recovery_health;
pub mod storage;

pub(crate) use crate::adapters::network::account_service as service;
pub(crate) use crate::adapters::network::capabilities;

pub use sesame_core::backup;
pub use sesame_core::platform;
pub use sesame_core::release_record;
pub use sesame_core::throttle;
pub use sesame_core::types;
pub use sesame_core::util;

pub use sesame_core::password_analysis::*;
pub use sesame_core::types::*;
pub use sesame_core::util::*;

pub use sesame_core::{UnlockedVault, VaultResult, VaultState, SERVICE_CONNECTION_FORMAT_VERSION};

pub fn report_key_page_fallback(app: &tauri::AppHandle, unlocked: &UnlockedVault) {
    if unlocked.key_uses_page_fallback() {
        crate::diagnostics::record_vault_key_fallback(app, "key_page_fallback");
    }
}

/// The desktop event half of locking; every lock entry point calls this so the behavior cannot drift.
pub fn lock_and_notify(state: &VaultState, app: &tauri::AppHandle) -> VaultResult<()> {
    crate::application::lifecycle::lock_and_notify(
        state,
        &crate::adapters::desktop_effects::DesktopHostEffects::new(app),
    )
}
