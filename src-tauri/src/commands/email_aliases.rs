use tauri::State;

use crate::adapters::network::email_alias;
use crate::application::email_aliases::{
    create_email_alias_in_state, email_alias_status_in_state, remove_email_alias_settings_in_state,
    save_email_alias_settings_in_state, EmailAliasSettingsInput, EmailAliasStatus,
};
use crate::vault::{VaultResult, VaultState};

#[tauri::command]
pub fn get_email_alias_settings(vault: State<'_, VaultState>) -> VaultResult<EmailAliasStatus> {
    email_alias_status_in_state(&vault)
}

#[tauri::command]
pub fn save_email_alias_settings(
    vault: State<'_, VaultState>,
    settings: EmailAliasSettingsInput,
) -> VaultResult<EmailAliasStatus> {
    save_email_alias_settings_in_state(&vault, settings)
}

#[tauri::command]
pub fn remove_email_alias_settings(vault: State<'_, VaultState>) -> VaultResult<EmailAliasStatus> {
    remove_email_alias_settings_in_state(&vault)
}

#[tauri::command]
pub async fn create_email_alias(
    vault: State<'_, VaultState>,
    site: Option<String>,
) -> VaultResult<String> {
    create_email_alias_in_state(&vault, site, |request| async move {
        email_alias::create_alias(&request).await
    })
    .await
}
