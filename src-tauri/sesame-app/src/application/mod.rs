pub mod document_attachments;

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::vault::recovery_health::RecoveryHealth;
use crate::vault::throttle::{PersistedPinThrottle, PinAttemptGuard};
use crate::vault::{UnlockedVault, VaultResult, VaultSnapshot, VaultState};

pub mod backups;
pub mod breach_scan;
pub mod browser_fill;
pub mod browser_fill_broker;
pub mod browser_replies;
pub mod file_choices;
pub mod history;
pub mod imports;
pub mod lifecycle;
pub mod logins;
pub mod quick_access;
pub mod record_writes;
pub mod records;
pub mod recovery_replacement;
pub mod release;
pub mod reveal;
pub mod search;
pub mod sync;
pub mod sync_adopt;
pub mod sync_join;
pub mod sync_pairing;
pub mod sync_recovery;
pub mod sync_transfer;
pub mod unlock;
pub mod updater;

#[cfg(test)]
pub mod backups_tests;

#[cfg(test)]
pub mod broker_tests;

#[cfg(test)]
pub mod browser_fill_tests;

#[cfg(test)]
pub mod browser_replies_tests;

#[cfg(test)]
pub mod imports_tests;

#[cfg(test)]
pub mod logins_tests;

#[cfg(test)]
pub mod quick_access_tests;

#[cfg(test)]
pub mod sync_pairing_tests;

#[cfg(test)]
pub mod sync_tests;

#[cfg(test)]
pub mod sync_transfer_tests;

#[cfg(test)]
pub mod tests;

#[cfg(test)]
pub mod unlock_lifecycle_tests;

#[cfg(test)]
pub mod updater_tests;

pub trait DesktopEffects: Sync {
    fn vault_path(&self) -> VaultResult<PathBuf>;
    fn report_key_page_fallback(&self, unlocked: &UnlockedVault);
    fn observe_unlock(&self, snapshot: &VaultSnapshot);
    fn observe_lock(&self, state: &VaultState);
    fn clear_armed_clipboard(&self) -> VaultResult<()>;
    fn copy_secret(
        &self,
        value: Zeroizing<String>,
        clear_after_ms: Option<u64>,
    ) -> VaultResult<u64>;
    fn revoke_presence(&self);
    fn cancel_breach_scan(&self);
    #[allow(clippy::result_unit_err)]
    fn emit_vault_locked(&self) -> Result<(), ()>;
    fn record_recovery_export(&self, vault_id: &str, revision: u64);
    fn record_recovery_verification(&self, vault_id: &str, revision: u64);
    fn recovery_health(&self, current_vault_id: Option<&str>) -> VaultResult<RecoveryHealth>;
    fn reset_rollback_after_restore(&self, vault_id: Option<&str>, revision: u64);
    fn cancel_pending_approvals(&self);
    fn report_backup_io_error(&self);
    fn read_pin_throttle_state(&self) -> VaultResult<Option<PersistedPinThrottle>>;
    fn write_pin_throttle_state(&self, guard: &PinAttemptGuard) -> VaultResult<()>;
    fn clear_pin_throttle_state(&self) -> VaultResult<()>;
    fn recovery_replacement_path(&self) -> VaultResult<PathBuf>;
    fn discard_recovery_replacement(&self);
    fn reset_rollback_record(&self, vault_id: &str, revision: u64) -> VaultResult<()>;
    fn record_browser_host_registration(&self, code: &'static str);
    fn emit_browser_approval_cancelled(
        &self,
        kind: browser_fill::ApprovalKind,
        approval_id: &str,
        reason: &'static str,
    );
    fn emit_breach_scan_progress(&self, checked: usize, total: usize);
    fn emit_breach_scan_finished(&self);
}
