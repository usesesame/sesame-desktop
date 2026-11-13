use std::path::PathBuf;

use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::application::breach_scan::{
    BreachScanProgress, BreachScanState, BREACH_SCAN_FINISHED_EVENT, BREACH_SCAN_PROGRESS_EVENT,
};
use crate::application::DesktopEffects;
use crate::release::ReleasePresence;
use crate::vault::recovery_health::RecoveryHealth;
use crate::vault::throttle::{PersistedPinThrottle, PinAttemptGuard};
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

    fn record_recovery_export(&self, vault_id: &str, revision: u64) {
        let _ = crate::vault::recovery_health::update_after_export_with_payload(
            self.app, vault_id, revision,
        );
    }

    fn record_recovery_verification(&self, vault_id: &str, revision: u64) {
        let _ = crate::vault::recovery_health::update_after_verification_with_payload(
            self.app, vault_id, revision,
        );
    }

    fn recovery_health(&self, current_vault_id: Option<&str>) -> VaultResult<RecoveryHealth> {
        crate::vault::recovery_health::get_health(self.app, current_vault_id)
    }

    fn reset_rollback_after_restore(&self, vault_id: Option<&str>, revision: u64) {
        crate::rollback_guard::reset_after_restore(self.app, vault_id, revision);
    }

    fn cancel_pending_approvals(&self) {
        crate::browser_fill::cancel_pending_approvals(self.app);
    }

    fn report_backup_io_error(&self) {
        crate::diagnostics::record_backup_io_error(self.app);
    }

    fn read_pin_throttle_state(&self) -> VaultResult<Option<PersistedPinThrottle>> {
        crate::vault::storage::read_pin_throttle_state(self.app)
    }

    fn write_pin_throttle_state(&self, guard: &PinAttemptGuard) -> VaultResult<()> {
        crate::vault::storage::write_pin_throttle_state(self.app, guard)
    }

    fn clear_pin_throttle_state(&self) -> VaultResult<()> {
        crate::vault::storage::clear_pin_throttle_state(self.app)
    }

    fn recovery_replacement_path(&self) -> VaultResult<PathBuf> {
        crate::application::recovery_replacement::request_path(&self.vault_path()?)
    }

    fn discard_recovery_replacement(&self) {
        if let Ok(path) = self.recovery_replacement_path() {
            let _ = crate::application::recovery_replacement::remove_request(&path);
        }
    }

    fn reset_rollback_record(&self, vault_id: &str, revision: u64) -> VaultResult<()> {
        let dir = crate::rollback_guard::data_dir(self.app)
            .ok_or("Sesame could not find its data folder.")?;
        crate::rollback_guard::reset(&dir, vault_id, revision)
    }

    fn record_browser_host_registration(&self, code: &'static str) {
        crate::diagnostics::record_browser_host_registration(self.app, code);
    }

    fn emit_browser_approval_cancelled(
        &self,
        kind: crate::application::browser_fill::ApprovalKind,
        approval_id: &str,
        reason: &'static str,
    ) {
        crate::browser_fill::emit_approval_cancelled(self.app, kind, approval_id, reason);
    }

    fn emit_breach_scan_progress(&self, checked: usize, total: usize) {
        let _ = self.app.emit(
            BREACH_SCAN_PROGRESS_EVENT,
            BreachScanProgress { checked, total },
        );
    }

    fn emit_breach_scan_finished(&self) {
        let _ = self.app.emit(BREACH_SCAN_FINISHED_EVENT, ());
    }
}
