use serde::{Deserialize, Serialize};
use std::path::Path;
use time::OffsetDateTime;

use super::{storage, VaultResult};

const MAX_RECOVERY_HEALTH_BYTES: u64 = 64 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryHealth {
    pub vault_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exported_revision: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    #[ts(optional, type = "string")]
    pub last_exported_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_revision: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    #[ts(optional, type = "string")]
    pub last_verified_at: Option<OffsetDateTime>,
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
    now: OffsetDateTime,
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
    now: OffsetDateTime,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_written_before_the_time_crate_still_reads() {
        let stored = br#"{"vaultId":"fictional-vault","lastExportedRevision":7,"lastExportedAt":"2026-10-10T12:00:00.123456789Z","lastVerifiedAt":"2026-10-10T14:00:00+02:00"}"#;
        let health: RecoveryHealth = serde_json::from_slice(stored).expect("record");
        assert_eq!(
            health.last_exported_at.map(|at| at.unix_timestamp()),
            Some(1_791_633_600)
        );
        assert_eq!(
            health.last_verified_at.map(|at| at.unix_timestamp()),
            Some(1_791_633_600)
        );
        assert_eq!(health.last_verified_revision, None);
    }

    #[test]
    fn a_record_keeps_its_times_as_utc_text_and_leaves_out_missing_ones() {
        let now = OffsetDateTime::from_unix_timestamp(1_791_633_600).expect("time");
        let health = record_export(RecoveryHealth::default(), "fictional-vault", 7, now);
        let written = serde_json::to_string(&health).expect("record");
        assert_eq!(
            written,
            r#"{"vaultId":"fictional-vault","lastExportedRevision":7,"lastExportedAt":"2026-10-10T12:00:00Z"}"#
        );
        let read: RecoveryHealth = serde_json::from_str(&written).expect("record");
        assert_eq!(read, health);
    }

    #[test]
    fn a_record_with_a_time_that_is_not_a_date_is_refused() {
        let stored = br#"{"vaultId":"fictional-vault","lastExportedAt":"yesterday"}"#;
        assert!(serde_json::from_slice::<RecoveryHealth>(stored).is_err());
    }
}
