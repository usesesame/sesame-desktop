use chrono::Utc;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

use super::VaultResult;

pub use sesame_app::vault::recovery_health::RecoveryHealth;

pub fn recovery_health_path(app: &AppHandle) -> VaultResult<PathBuf> {
    let mut path = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
    path.push(super::backup::RECOVERY_HEALTH_FILE);
    Ok(path)
}

pub fn read_recovery_health(app: &AppHandle) -> VaultResult<Option<RecoveryHealth>> {
    sesame_app::vault::recovery_health::read_recovery_health_at(&recovery_health_path(app)?)
}

pub fn write_recovery_health(app: &AppHandle, health: &RecoveryHealth) -> VaultResult<()> {
    sesame_app::vault::recovery_health::write_recovery_health_at(
        &recovery_health_path(app)?,
        health,
    )
}

pub fn update_after_export_with_payload(
    app: &AppHandle,
    vault_id: &str,
    revision: u64,
) -> VaultResult<()> {
    let health = read_recovery_health(app)?.unwrap_or_default();
    let health =
        sesame_app::vault::recovery_health::record_export(health, vault_id, revision, Utc::now());
    write_recovery_health(app, &health)
}

pub fn update_after_verification_with_payload(
    app: &AppHandle,
    vault_id: &str,
    revision: u64,
) -> VaultResult<()> {
    let health = read_recovery_health(app)?.unwrap_or_default();
    let Some(health) = sesame_app::vault::recovery_health::record_verification(
        health,
        vault_id,
        revision,
        Utc::now(),
    ) else {
        return Ok(());
    };
    write_recovery_health(app, &health)
}

pub fn get_health(app: &AppHandle, current_vault_id: Option<&str>) -> VaultResult<RecoveryHealth> {
    match read_recovery_health(app)? {
        Some(health) => {
            if current_vault_id.is_some_and(|id| id != health.vault_id) {
                Ok(RecoveryHealth {
                    vault_id: current_vault_id.unwrap_or_default().into(),
                    ..Default::default()
                })
            } else {
                Ok(health)
            }
        }
        None => Ok(RecoveryHealth {
            vault_id: current_vault_id.unwrap_or_default().into(),
            ..Default::default()
        }),
    }
}
