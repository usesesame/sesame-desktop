use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::{storage, VaultResult};

const MAX_RECOVERY_HEALTH_BYTES: u64 = 64 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryHealth {
    pub vault_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exported_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "string")]
    pub last_exported_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "string")]
    pub last_verified_at: Option<DateTime<Utc>>,
}

pub fn read_recovery_health_at(path: &Path) -> VaultResult<Option<RecoveryHealth>> {
    let bytes = match super::util::read_file_with_limit(path, MAX_RECOVERY_HEALTH_BYTES) {
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

pub fn write_recovery_health_at(path: &Path, health: &RecoveryHealth) -> VaultResult<()> {
    let bytes = serde_json::to_vec(health)
        .map_err(|_| "Sesame could not save the recovery health record.".to_string())?;
    storage::atomic_replace(path, &bytes)
}

pub fn record_export(
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

pub fn record_verification(
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
