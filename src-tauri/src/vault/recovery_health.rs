use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

use super::{storage, VaultResult};

const MAX_RECOVERY_HEALTH_BYTES: u64 = 64 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryHealth {
    pub vault_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exported_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exported_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<DateTime<Utc>>,
}

pub fn recovery_health_path(app: &AppHandle) -> VaultResult<PathBuf> {
    let mut path = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
    path.push(super::backup::RECOVERY_HEALTH_FILE);
    Ok(path)
}

pub fn read_recovery_health(app: &AppHandle) -> VaultResult<Option<RecoveryHealth>> {
    let path = recovery_health_path(app)?;
    let bytes = match super::util::read_file_with_limit(&path, MAX_RECOVERY_HEALTH_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            return Err("The recovery health record is not valid.".into())
        }
        Err(_) => return Err("Sesame could not read the recovery health record.".into()),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "The recovery health record is not valid.".into())
}

pub fn write_recovery_health(app: &AppHandle, health: &RecoveryHealth) -> VaultResult<()> {
    let path = recovery_health_path(app)?;
    let bytes = serde_json::to_vec(health)
        .map_err(|_| "Sesame could not save the recovery health record.".to_string())?;
    storage::atomic_replace(&path, &bytes)
}

pub fn update_after_export_with_payload(
    app: &AppHandle,
    vault_id: &str,
    revision: u64,
) -> VaultResult<()> {
    let health = read_recovery_health(app)?.unwrap_or_default();
    let health = record_export(health, vault_id, revision, Utc::now());
    write_recovery_health(app, &health)
}

pub fn update_after_verification_with_payload(
    app: &AppHandle,
    vault_id: &str,
    revision: u64,
) -> VaultResult<()> {
    let health = read_recovery_health(app)?.unwrap_or_default();
    let Some(health) = record_verification(health, vault_id, revision, Utc::now()) else {
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

fn record_export(
    mut health: RecoveryHealth,
    vault_id: &str,
    revision: u64,
    now: DateTime<Utc>,
) -> RecoveryHealth {
    if health.vault_id != vault_id {
        health = RecoveryHealth {
            vault_id: vault_id.into(),
            ..Default::default()
        };
    }
    health.last_exported_revision = Some(revision);
    health.last_exported_at = Some(now);
    health
}

fn record_verification(
    mut health: RecoveryHealth,
    vault_id: &str,
    revision: u64,
    now: DateTime<Utc>,
) -> Option<RecoveryHealth> {
    if health.vault_id.is_empty() {
        health.vault_id = vault_id.into();
    }
    if health.vault_id != vault_id {
        return None;
    }
    health.last_verified_revision = Some(revision);
    health.last_verified_at = Some(now);
    Some(health)
}
