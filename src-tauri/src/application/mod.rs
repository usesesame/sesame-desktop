pub(crate) mod document_attachments;

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::vault::{UnlockedVault, VaultResult, VaultSnapshot, VaultState};

pub(crate) mod lifecycle;
pub(crate) mod records;
pub(crate) mod release;
pub(crate) mod reveal;
pub(crate) mod search;

#[cfg(test)]
mod tests;

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
}
