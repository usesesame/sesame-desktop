use std::path::Path;

use sesame_core::VaultResult;

use super::protection::DEVICE_PROTECTOR;

pub use sesame_sync::floor::*;

pub fn record_manifest_floor(
    path: &Path,
    manifest: &serde_json::Value,
    encoded_public_key: &str,
    expected_key_id: &str,
    now: u64,
) -> VaultResult<Option<StoredFloor>> {
    record_manifest_floor_with(
        path,
        manifest,
        encoded_public_key,
        expected_key_id,
        now,
        &DEVICE_PROTECTOR,
    )
}

pub fn confirmed_at(path: &Path) -> Option<u64> {
    confirmed_at_with(path, &DEVICE_PROTECTOR)
}

pub fn require_allowed(build_version: &str, path: &Path, can_fetch: bool) -> Result<(), String> {
    require_allowed_with(
        build_version,
        sesame_sync::DESKTOP_PLATFORM,
        path,
        can_fetch,
        &DEVICE_PROTECTOR,
    )
}
