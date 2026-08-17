//! Standalone local tools that touch no vault state; nothing here needs an unlocked session.
//! The breach request is delegated to the network adapter; this module owns the Tauri-facing API.

use crate::adapters::network::breach::{self, BreachCheckResult};
use crate::vault::{analyse_password_value, PasswordAnalysis, VaultResult};

#[tauri::command]
pub fn check_password_strength(password: String) -> PasswordAnalysis {
    analyse_password_value(&password)
}

/// Only a 5-character hash prefix is sent; a network failure is never mistaken for a clean password.
#[tauri::command]
pub async fn check_password_breach(password: String) -> VaultResult<BreachCheckResult> {
    breach::check_password_breach(password).await
}
