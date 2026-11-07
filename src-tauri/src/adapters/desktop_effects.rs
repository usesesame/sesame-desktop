use std::path::PathBuf;

use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::application::DesktopEffects;
use crate::commands::BreachScanState;
use crate::release::ReleasePresence;
use crate::vault::{UnlockedVault, VaultResult, VaultSnapshot, VaultState};

pub(crate) struct DesktopHostEffects<'a> {
    app: &'a AppHandle,
}

impl<'a> DesktopHostEffects<'a> {
    pub(crate) fn new(app: &'a AppHandle) -> Self {
        Self { app }
    }
}

impl DesktopEffects for DesktopHostEffects<'_> {
    fn vault_path(&self) -> VaultResult<PathBuf> {
        crate::vault::storage::vault_path(self.app)
    }

    fn report_key_page_fallback(&self, unlocked: &UnlockedVault) {
        crate::vault::report_key_page_fallback(self.app, unlocked);
    }

    fn observe_unlock(&self, snapshot: &VaultSnapshot) {
        crate::rollback_guard::observe_unlock(self.app, snapshot);
    }

    fn observe_lock(&self, state: &VaultState) {
        crate::rollback_guard::observe_lock(self.app, state);
    }

    fn clear_armed_clipboard(&self) -> VaultResult<()> {
        crate::adapters::platform::clipboard::clear_armed_clipboard(self.app)
    }

    fn copy_secret(
        &self,
        value: Zeroizing<String>,
        clear_after_ms: Option<u64>,
    ) -> VaultResult<u64> {
        let clipboard = self
            .app
            .try_state::<crate::adapters::platform::clipboard::ClipboardGuard>()
            .ok_or("Sesame could not reach the clipboard.")?;
        crate::adapters::platform::clipboard::copy_secret_value(
            self.app.clone(),
            &clipboard,
            value.to_string(),
            clear_after_ms,
        )
    }

    fn revoke_presence(&self) {
        if let Some(presence) = self.app.try_state::<ReleasePresence>() {
            presence.revoke();
        }
    }

    fn cancel_breach_scan(&self) {
        if let Some(scan) = self.app.try_state::<BreachScanState>() {
            scan.cancel();
        }
    }

    fn emit_vault_locked(&self) -> Result<(), ()> {
        self.app.emit("vault-locked", ()).map_err(|_| ())
    }

    fn establish_pin_throttle_state(&self, state: &VaultState) -> VaultResult<()> {
        crate::commands::establish_pin_throttle_state(self.app, state)
    }

    fn cancel_pending_approvals(&self) {
        crate::browser_fill::cancel_pending_approvals(self.app);
    }

    fn report_backup_io_error(&self) {
        crate::diagnostics::record_backup_io_error(self.app);
    }
}
