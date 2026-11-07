pub(crate) mod document_attachments;

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::vault::recovery_health::RecoveryHealth;
use crate::vault::throttle::{PersistedPinThrottle, PinAttemptGuard};
use crate::vault::{UnlockedVault, VaultResult, VaultSnapshot, VaultState};

pub(crate) mod backups;
pub(crate) mod breach_scan;
pub(crate) mod browser_fill;
pub(crate) mod browser_fill_broker;
pub(crate) mod browser_replies;
pub(crate) mod file_choices;
pub(crate) mod history;
pub(crate) mod imports;
pub(crate) mod lifecycle;
pub(crate) mod logins;
pub(crate) mod quick_access;
pub(crate) mod record_writes;
pub(crate) mod records;
pub(crate) mod recovery_replacement;
pub(crate) mod release;
pub(crate) mod reveal;
pub(crate) mod search;
pub(crate) mod sync;
pub(crate) mod sync_pairing;
pub(crate) mod sync_recovery;
pub(crate) mod unlock;

#[cfg(test)]
mod backups_tests;

#[cfg(test)]
pub(crate) mod broker_tests;

#[cfg(test)]
mod browser_fill_tests;

#[cfg(test)]
mod browser_replies_tests;

#[cfg(test)]
mod imports_tests;

#[cfg(test)]
mod logins_tests;

#[cfg(test)]
mod quick_access_tests;

#[cfg(test)]
mod record_writes_tests;

#[cfg(test)]
mod sync_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod unlock_lifecycle_tests;

pub(crate) trait DesktopEffects {
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
    fn emit_vault_locked(&self) -> Result<(), ()>;
    fn establish_pin_throttle_state(&self, state: &VaultState) -> VaultResult<()>;
    fn record_recovery_export(&self, vault_id: &str, revision: u64);
    fn record_recovery_verification(&self, vault_id: &str, revision: u64);
    fn recovery_health(&self, current_vault_id: Option<&str>) -> VaultResult<RecoveryHealth>;
    fn reset_rollback_after_restore(&self, vault_id: Option<&str>, revision: u64);
    fn discard_pin_throttle_state(&self, state: &VaultState);
    fn cancel_pending_approvals(&self);
    fn report_backup_io_error(&self);
    fn read_pin_throttle_state(&self) -> VaultResult<Option<PersistedPinThrottle>>;
    fn write_pin_throttle_state(&self, guard: &PinAttemptGuard) -> VaultResult<()>;
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
